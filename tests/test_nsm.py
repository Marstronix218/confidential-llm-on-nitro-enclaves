"""enclave/nsm.py against a fake NSM driver (monkeypatched fcntl.ioctl), no Nitro hardware needed."""
import ctypes
import types

import cbor2
import pytest

import nsm


def test_ioctl_request_number():
    # _IOWR(0x0A, 0x00, struct NsmMessage): two iovecs of (pointer, size_t) = 32 bytes on 64-bit Linux
    assert ctypes.sizeof(nsm.NsmMessage) == 4 * ctypes.sizeof(ctypes.c_void_p)
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        assert nsm.NSM_IOCTL_REQUEST == 0xC0200A00 == 3223325184


@pytest.fixture
def fake_device(tmp_path, monkeypatch):
    """Point nsm at a regular file standing in for /dev/nsm; reset its warn-once flag."""
    device = tmp_path / "nsm"
    device.write_bytes(b"")
    monkeypatch.setattr(nsm, "NSM_DEV_FILE", str(device))
    monkeypatch.setattr(nsm, "_warned", False)
    return device


def install_driver(monkeypatch, response: dict, seen: dict):
    """Fake driver: decode the request iovec, write `response` (CBOR) into the response iovec."""

    def ioctl(fd, op, message):
        seen["op"] = op
        seen["request"] = cbor2.loads(ctypes.string_at(message.request.iov_base, message.request.iov_len))
        seen["response_capacity"] = message.response.iov_len
        out = cbor2.dumps(response)
        assert len(out) <= message.response.iov_len
        ctypes.memmove(message.response.iov_base, out, len(out))
        message.response.iov_len = len(out)
        return 0

    monkeypatch.setattr(nsm, "fcntl", types.SimpleNamespace(ioctl=ioctl))


def test_attestation_request_shape_and_response(fake_device, monkeypatch):
    seen = {}
    install_driver(monkeypatch, {"Attestation": {"document": b"COSE-SIGN1-DOC"}}, seen)

    document = nsm.get_attestation_document(public_key_der=b"DER-KEY", nonce=b"N" * 32, user_data=None)

    assert document == b"COSE-SIGN1-DOC"
    assert seen["op"] == nsm.NSM_IOCTL_REQUEST
    assert seen["request"] == {
        "Attestation": {"user_data": None, "nonce": b"N" * 32, "public_key": b"DER-KEY"}
    }
    assert seen["response_capacity"] == nsm.NSM_RESPONSE_MAX_SIZE


def test_missing_device_returns_none(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(nsm, "NSM_DEV_FILE", str(tmp_path / "does-not-exist"))
    monkeypatch.setattr(nsm, "_warned", False)

    assert nsm.get_attestation_document(b"DER", None, None) is None
    assert nsm.get_attestation_document(b"DER", None, None) is None
    assert capsys.readouterr().out.count("unavailable") == 1  # warned once


def test_error_response_returns_none(fake_device, monkeypatch, capsys):
    install_driver(monkeypatch, {"Error": "InvalidArgument"}, {})

    assert nsm.get_attestation_document(b"DER", b"nonce", None) is None
    assert "InvalidArgument" in capsys.readouterr().out


def test_ioctl_failure_returns_none(fake_device, monkeypatch):
    def ioctl(fd, op, message):
        raise OSError(25, "Inappropriate ioctl for device")

    monkeypatch.setattr(nsm, "fcntl", types.SimpleNamespace(ioctl=ioctl))
    assert nsm.get_attestation_document(b"DER", None, None) is None


def test_oversize_request_returns_none(fake_device, monkeypatch):
    install_driver(monkeypatch, {"Attestation": {"document": b"doc"}}, {})
    assert nsm.get_attestation_document(b"x" * (nsm.NSM_REQUEST_MAX_SIZE + 1), None, None) is None
