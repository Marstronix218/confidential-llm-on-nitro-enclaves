"""Verify AWS Nitro Enclaves attestation documents (pure Python: cbor2 + cryptography).

Follows the AWS "Nitro Enclaves attestation process" spec
(https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md):

  * the document is a COSE_Sign1 structure (CBOR tag 18, optional) signed with ES384;
  * its payload is a CBOR map: module_id, digest, timestamp, pcrs, certificate, cabundle,
    public_key, user_data, nonce;
  * the signing certificate chains certificate <- cabundle[N] <- ... <- cabundle[0], where
    cabundle[0] is the AWS Nitro Enclaves root and must equal the trusted root we pin.

verify_attestation() never raises on a malformed document; every problem becomes an entry in
AttestationResult.errors and verified is True only when that list is empty.
"""
from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

COSE_SIGN1_TAG = 18
COSE_HEADER_ALG = 1
COSE_ALG_ES384 = -35
ES384_SIGNATURE_SIZE = 96  # raw r || s, 48 bytes each

# AWS Nitro Enclaves Root-G1, root.pem from
# https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
# SHA-256 fingerprint of the DER certificate, as published at
# https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html :
#   64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B
# (checked by tests/test_attestation.py). Subject CN=aws.nitro-enclaves, valid until 2049-10-28.
AWS_NITRO_ROOT_PEM: bytes | None = b"""-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
"""


@dataclass
class AttestationResult:
    verified: bool = False
    pcrs: dict[int, str] = field(default_factory=dict)
    module_id: str = ""
    timestamp: datetime | None = None
    errors: list[str] = field(default_factory=list)


def verify_attestation(
    doc: bytes,
    *,
    expected_nonce: bytes | None,
    expected_public_key_der: bytes,
    expected_pcrs: dict[int, str],
    root_cert_pem: bytes | None = None,
    now: datetime | None = None,
) -> AttestationResult:
    """Verify a Nitro attestation document. root_cert_pem defaults to AWS_NITRO_ROOT_PEM."""
    result = AttestationResult()
    errors = result.errors
    if root_cert_pem is None:
        root_cert_pem = AWS_NITRO_ROOT_PEM
    if now is None:
        now = datetime.now(timezone.utc)

    try:
        decoded = _decode(doc, errors)
        if decoded is None:
            return result
        protected, payload_bytes, signature, payload = decoded

        result.module_id = payload["module_id"]
        result.timestamp = datetime.fromtimestamp(payload["timestamp"] / 1000, tz=timezone.utc)
        result.pcrs = {index: value.hex() for index, value in sorted(payload["pcrs"].items())}

        leaf = _check_chain(payload["certificate"], payload["cabundle"], root_cert_pem, now, errors)
        if leaf is not None:
            _check_signature(leaf, protected, payload_bytes, signature, errors)
        _check_bindings(payload, result.pcrs, expected_nonce, expected_public_key_der, expected_pcrs, errors)
    except Exception as e:  # never raise on a malformed document
        errors.append(f"unexpected error while verifying attestation: {type(e).__name__}: {e}")

    result.verified = not errors
    return result


def _decode(doc, errors):
    """Parse COSE_Sign1 + payload; returns (protected, payload_bytes, signature, payload) or None."""
    if not isinstance(doc, (bytes, bytearray)) or not doc:
        errors.append("attestation document is empty or not bytes")
        return None
    try:
        obj = cbor2.loads(bytes(doc))
    except Exception as e:
        errors.append(f"attestation document is not valid CBOR: {e}")
        return None

    if isinstance(obj, cbor2.CBORTag):
        if obj.tag != COSE_SIGN1_TAG:
            errors.append(f"unexpected CBOR tag {obj.tag} (expected {COSE_SIGN1_TAG}, COSE_Sign1)")
            return None
        obj = obj.value
    if not isinstance(obj, (list, tuple)) or len(obj) != 4:  # cbor2 decodes arrays inside a tag as tuples
        errors.append("attestation document is not a COSE_Sign1 array of 4 elements")
        return None

    protected, unprotected, payload_bytes, signature = obj
    if not isinstance(protected, bytes) or not isinstance(payload_bytes, bytes) or not isinstance(signature, bytes):
        errors.append("COSE_Sign1 protected header, payload and signature must be byte strings")
        return None
    if not isinstance(unprotected, Mapping):
        errors.append("COSE_Sign1 unprotected header must be a map")
        return None

    try:
        header = cbor2.loads(protected) if protected else {}
    except Exception as e:
        errors.append(f"COSE protected header is not valid CBOR: {e}")
        return None
    if not isinstance(header, Mapping) or header.get(COSE_HEADER_ALG) != COSE_ALG_ES384:
        errors.append(f"COSE algorithm must be ES384 ({COSE_ALG_ES384}), got header {header!r}")
        return None

    try:
        payload = cbor2.loads(payload_bytes)
    except Exception as e:
        errors.append(f"attestation payload is not valid CBOR: {e}")
        return None
    if not isinstance(payload, Mapping):
        errors.append("attestation payload is not a CBOR map")
        return None
    if not _check_payload_fields(payload, errors):
        return None
    return protected, payload_bytes, signature, payload


def _check_payload_fields(payload, errors):
    """Syntactic checks from the AWS spec. Returns False when the payload cannot be used at all."""
    before = len(errors)

    module_id = payload.get("module_id")
    if not isinstance(module_id, str) or not module_id:
        errors.append("module_id missing or empty")
    if payload.get("digest") != "SHA384":
        errors.append(f"digest must be 'SHA384', got {payload.get('digest')!r}")
    timestamp = payload.get("timestamp")
    if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp <= 0:
        errors.append("timestamp missing or not a positive integer")

    pcrs = payload.get("pcrs")
    if not isinstance(pcrs, Mapping) or not 1 <= len(pcrs) <= 32:
        errors.append("pcrs must be a map with 1 to 32 entries")
    else:
        for index, value in pcrs.items():
            if not isinstance(index, int) or not 0 <= index < 32:
                errors.append(f"invalid PCR index {index!r}")
            elif not isinstance(value, bytes) or len(value) not in (32, 48, 64):
                errors.append(f"PCR{index} must be 32, 48 or 64 bytes")

    if not isinstance(payload.get("certificate"), bytes) or not payload["certificate"]:
        errors.append("certificate missing or not a byte string")
    cabundle = payload.get("cabundle")
    if (not isinstance(cabundle, (list, tuple)) or not cabundle
            or not all(isinstance(c, bytes) and c for c in cabundle)):
        errors.append("cabundle must be a non-empty array of byte strings")

    for name, max_len in (("public_key", 1024), ("user_data", 512), ("nonce", 512)):
        value = payload.get(name)
        if value is not None and (not isinstance(value, bytes) or len(value) > max_len):
            errors.append(f"{name} must be null or a byte string of at most {max_len} bytes")

    return len(errors) == before


def _check_chain(certificate_der, cabundle, root_cert_pem, now, errors):
    """Validate certificate <- cabundle[1:] <- trusted root. Returns the leaf cert or None."""
    if not root_cert_pem:
        errors.append("no trusted root certificate configured (AWS_NITRO_ROOT_PEM is not set)")
        return None
    try:
        root = x509.load_pem_x509_certificate(root_cert_pem)
        bundle = [x509.load_der_x509_certificate(der) for der in cabundle]
        leaf = x509.load_der_x509_certificate(certificate_der)
    except Exception as e:
        errors.append(f"cannot parse certificates: {e}")
        return None

    der = serialization.Encoding.DER
    if bundle[0].public_bytes(der) != root.public_bytes(der):
        errors.append("cabundle[0] is not the trusted root certificate")

    chain = [root] + bundle[1:] + [leaf]  # root first, leaf last
    for position, cert in enumerate(chain):
        name = "root" if position == 0 else ("leaf" if cert is leaf else f"cabundle[{position}]")
        if now < cert.not_valid_before_utc:
            errors.append(f"{name} certificate is not valid yet (not before {cert.not_valid_before_utc})")
        if now > cert.not_valid_after_utc:
            errors.append(f"{name} certificate has expired (not after {cert.not_valid_after_utc})")
        if position == 0:
            continue
        issuer = chain[position - 1]
        try:
            constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
            is_ca = constraints.ca
        except x509.ExtensionNotFound:
            is_ca = False
        if not is_ca:
            errors.append(f"issuer of {name} certificate is not a CA")
        try:
            cert.verify_directly_issued_by(issuer)
        except (ValueError, TypeError, InvalidSignature) as e:
            errors.append(f"{name} certificate is not signed by its issuer: {type(e).__name__} {e}".rstrip())

    leaf_key = leaf.public_key()
    if not isinstance(leaf_key, ec.EllipticCurvePublicKey) or not isinstance(leaf_key.curve, ec.SECP384R1):
        errors.append("leaf certificate key is not an EC P-384 key")
        return None
    return leaf


def _check_signature(leaf, protected, payload_bytes, signature, errors):
    if len(signature) != ES384_SIGNATURE_SIZE:
        errors.append(f"COSE signature must be {ES384_SIGNATURE_SIZE} bytes, got {len(signature)}")
        return
    half = ES384_SIGNATURE_SIZE // 2
    der_signature = encode_dss_signature(
        int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big")
    )
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload_bytes])
    try:
        leaf.public_key().verify(der_signature, sig_structure, ec.ECDSA(hashes.SHA384()))
    except InvalidSignature:
        errors.append("COSE signature verification failed")


def _check_bindings(payload, pcrs, expected_nonce, expected_public_key_der, expected_pcrs, errors):
    for index, expected in sorted((expected_pcrs or {}).items()):
        if not expected:
            continue  # not configured: not compared
        actual = pcrs.get(index)
        if actual is None:
            errors.append(f"PCR{index} missing from document")
        elif actual.lower() != expected.strip().lower():
            errors.append(f"PCR{index} mismatch: expected {expected.strip().lower()}, got {actual}")

    if expected_nonce is not None:
        nonce = payload.get("nonce")
        if nonce is None or not hmac.compare_digest(nonce, expected_nonce):
            errors.append("nonce mismatch")

    public_key = payload.get("public_key")
    if public_key is None or not hmac.compare_digest(public_key, expected_public_key_der or b""):
        errors.append("public_key mismatch")
