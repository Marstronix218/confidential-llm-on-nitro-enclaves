"""Synthetic Nitro attestation documents for tests (control-plane/api/tests and tests/test_chat.py).

A throwaway P-384 CA hierarchy (root -> intermediate -> leaf) and a COSE_Sign1/ES384 signer for a
payload shaped like the AWS spec. Pass make_pki()["root_pem"] to verify_attestation (or patch
attestation.AWS_NITRO_ROOT_PEM with it) to make the documents verifiable.
"""
from datetime import datetime, timedelta, timezone

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

NOW = datetime.now(timezone.utc).replace(microsecond=0)
DER = serialization.Encoding.DER
PCR0 = bytes.fromhex("a1" * 48)
PCR1 = bytes.fromhex("b2" * 48)
PCR2 = bytes.fromhex("c3" * 48)
NONCE = b"n" * 32
MODULE_ID = "i-0123456789abcdef0-enc0123456789abcd"


def make_cert(subject_cn, key, issuer_cert=None, issuer_key=None, *, ca, not_before, not_after):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = issuer_cert.subject if issuer_cert else subject
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    return builder.sign(issuer_key or key, hashes.SHA384())


def make_ca(cn="test-nitro-root"):
    key = ec.generate_private_key(ec.SECP384R1())
    cert = make_cert(cn, key, ca=True, not_before=NOW - timedelta(days=1), not_after=NOW + timedelta(days=3650))
    return cert, key


def make_pki(root_cn="test-nitro-root"):
    root, root_key = make_ca(root_cn)
    inter_key = ec.generate_private_key(ec.SECP384R1())
    inter = make_cert("test-intermediate", inter_key, root, root_key, ca=True,
                      not_before=NOW - timedelta(days=1), not_after=NOW + timedelta(days=30))
    leaf_key = ec.generate_private_key(ec.SECP384R1())
    # Real Nitro leaf certificates are short-lived (about 3 hours)
    leaf = make_cert("test-enclave", leaf_key, inter, inter_key, ca=False,
                     not_before=NOW - timedelta(minutes=5), not_after=NOW + timedelta(hours=3))
    enclave_pub_der = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    return {
        "root": root, "root_pem": root.public_bytes(serialization.Encoding.PEM),
        "inter": inter, "leaf": leaf, "leaf_key": leaf_key, "public_key": enclave_pub_der,
    }


def build_payload(pki, *, public_key=None, nonce=NONCE, pcrs=(PCR0, PCR1, PCR2)):
    """CBOR attestation payload; public_key defaults to pki["public_key"], pcrs are PCR0-2 (bytes)."""
    all_pcrs = {i: bytes(48) for i in range(16)}
    all_pcrs.update(enumerate(pcrs))
    return cbor2.dumps({
        "module_id": MODULE_ID,
        "digest": "SHA384",
        "timestamp": int(NOW.timestamp() * 1000),
        "pcrs": all_pcrs,
        "certificate": pki["leaf"].public_bytes(DER),
        "cabundle": [pki["root"].public_bytes(DER), pki["inter"].public_bytes(DER)],  # root first
        "public_key": pki["public_key"] if public_key is None else public_key,
        "user_data": None,
        "nonce": nonce,
    })


def sign_document(payload, signing_key, tag=True):
    protected = cbor2.dumps({1: -35})  # alg: ES384
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    r, s = decode_dss_signature(signing_key.sign(sig_structure, ec.ECDSA(hashes.SHA384())))
    signature = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    cose = [protected, {}, payload, signature]
    return cbor2.dumps(cbor2.CBORTag(18, cose) if tag else cose)
