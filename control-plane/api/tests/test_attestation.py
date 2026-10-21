"""Tests for attestation.verify_attestation against a synthetic Nitro attestation document.

A throwaway P-384 CA hierarchy (root -> intermediate -> leaf, see pki.py) is generated, a payload
shaped like the AWS spec is COSE_Sign1-signed with ES384, and verification is checked to pass with the
right expectations and to fail, with a specific error, for each kind of tampering.
"""
import sys
from datetime import timedelta
from pathlib import Path

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attestation import AWS_NITRO_ROOT_PEM, verify_attestation  # noqa: E402
from pki import (DER, MODULE_ID, NONCE, NOW, PCR0, PCR1, PCR2, build_payload, make_ca,  # noqa: E402
                 make_cert, make_pki, sign_document)


@pytest.fixture(scope="module")
def pki():
    return make_pki()


def verify(doc, pki, **overrides):
    kwargs = {
        "expected_nonce": NONCE,
        "expected_public_key_der": pki["public_key"],
        "expected_pcrs": {0: PCR0.hex(), 1: PCR1.hex().upper(), 2: PCR2.hex()},
        "root_cert_pem": pki["root_pem"],
        "now": NOW,
    }
    kwargs.update(overrides)
    return verify_attestation(doc, **kwargs)


@pytest.fixture(scope="module")
def doc(pki):
    return sign_document(build_payload(pki), pki["leaf_key"])


def assert_fails_with(result, fragment):
    assert not result.verified
    assert any(fragment in e for e in result.errors), result.errors


@pytest.mark.parametrize("tag", [True, False])
def test_valid_document_verifies(pki, tag):
    result = verify(sign_document(build_payload(pki), pki["leaf_key"], tag=tag), pki)
    assert result.verified, result.errors
    assert result.errors == []
    assert result.module_id == MODULE_ID
    assert result.timestamp == NOW
    assert result.pcrs[0] == PCR0.hex() and result.pcrs[2] == PCR2.hex()
    assert result.pcrs[5] == "00" * 48


def test_wrong_nonce(doc, pki):
    assert_fails_with(verify(doc, pki, expected_nonce=b"x" * 32), "nonce mismatch")


def test_wrong_public_key(doc, pki):
    other = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    assert_fails_with(verify(doc, pki, expected_public_key_der=other), "public_key mismatch")


def test_wrong_pcr0(doc, pki):
    expected = {0: "ff" * 48, 1: PCR1.hex(), 2: PCR2.hex()}
    result = verify(doc, pki, expected_pcrs=expected)
    assert_fails_with(result, "PCR0 mismatch")
    assert len(result.errors) == 1


def test_tampered_payload_byte(doc, pki):
    tag = cbor2.loads(doc)
    protected, unprotected, payload, signature = tag.value
    index = payload.index(MODULE_ID.encode()) + len(MODULE_ID) - 1
    tampered = payload[:index] + bytes([payload[index] ^ 0x01]) + payload[index + 1:]
    result = verify(cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, tampered, signature])), pki)
    assert_fails_with(result, "COSE signature verification failed")


def test_untrusted_root(doc, pki):
    other_root, _ = make_ca("attacker-root")
    result = verify(doc, pki, root_cert_pem=other_root.public_bytes(serialization.Encoding.PEM))
    assert_fails_with(result, "cabundle[0] is not the trusted root certificate")


def test_document_signed_under_attacker_root(pki):
    # A complete, self-consistent chain under a root we do not trust must still be rejected
    root, root_key = make_ca("attacker-root")
    leaf_key = ec.generate_private_key(ec.SECP384R1())
    leaf = make_cert("attacker-enclave", leaf_key, root, root_key, ca=False,
                     not_before=NOW - timedelta(minutes=5), not_after=NOW + timedelta(hours=3))
    fake = dict(cbor2.loads(build_payload(pki)))
    fake["certificate"] = leaf.public_bytes(DER)
    fake["cabundle"] = [root.public_bytes(DER)]
    result = verify(sign_document(cbor2.dumps(fake), leaf_key), pki)
    assert_fails_with(result, "cabundle[0] is not the trusted root certificate")
    assert_fails_with(result, "not signed by its issuer")


def test_expired_leaf(doc, pki):
    later = pki["leaf"].not_valid_after_utc + timedelta(days=1)
    result = verify(doc, pki, now=later)
    assert_fails_with(result, "leaf certificate has expired")
    assert all("leaf" in e for e in result.errors), result.errors


def test_default_root_rejects_synthetic_document(doc, pki):
    result = verify_attestation(doc, expected_nonce=NONCE, expected_public_key_der=pki["public_key"],
                                expected_pcrs={}, root_cert_pem=None, now=NOW)
    # root_cert_pem=None means the embedded AWS root; a synthetic doc never chains to it
    assert_fails_with(result, "cabundle[0] is not the trusted root certificate")


def test_embedded_aws_root_fingerprint():
    # Published at https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
    expected = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
    cert = x509.load_pem_x509_certificate(AWS_NITRO_ROOT_PEM)
    assert cert.fingerprint(hashes.SHA256()).hex() == expected
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "aws.nitro-enclaves"


@pytest.mark.parametrize("garbage", [b"", b"\x00", b"not cbor at all \xff\xff", cbor2.dumps([1, 2, 3]),
                                     cbor2.dumps(cbor2.CBORTag(18, [b"", {}, b"\xa0", b""]))])
def test_malformed_documents_never_raise(pki, garbage):
    result = verify(garbage, pki)
    assert not result.verified
    assert result.errors
