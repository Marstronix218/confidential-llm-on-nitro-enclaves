"""Attestation documents from the Nitro Security Module (/dev/nsm).

Re-implementation of the request path of the PyPI package `aws-nsm-interface`
1.0.0 (https://github.com/donkersgoed/aws-nsm-interface, MIT licence;
aws_nsm_interface/__init__.py and structs.py): the request is the CBOR map
{"Attestation": {"user_data", "nonce", "public_key"}}, passed to the device
through an ioctl _IOWR(0x0A, 0x00, struct NsmMessage) whose two iovecs point
at the request and response buffers. The response is CBOR
{"Attestation": {"document": <COSE_Sign1 bytes>}} or {"Error": ...}.
Inlined here (fcntl + ctypes + cbor2) to avoid the extra ioctl-opt dependency.

Outside a Nitro Enclave (local mock mode) there is no /dev/nsm, so
get_attestation_document() returns None and the client sees no document.
"""

import ctypes
import fcntl
import os

import cbor2

NSM_DEV_FILE = "/dev/nsm"
NSM_IOCTL_MAGIC = 0x0A
NSM_IOCTL_NUMBER = 0x00
NSM_REQUEST_MAX_SIZE = 0x1000
NSM_RESPONSE_MAX_SIZE = 0x3000

# Linux asm-generic/ioctl.h: dir << 30 | size << 16 | type << 8 | nr
_IOC_WRITE = 1
_IOC_READ = 2


class IoVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


class NsmMessage(ctypes.Structure):
    _fields_ = [("request", IoVec), ("response", IoVec)]


# _IOWR(NSM_IOCTL_MAGIC, 0, struct NsmMessage); 3223325184 on 64-bit Linux
NSM_IOCTL_REQUEST = (
    ((_IOC_READ | _IOC_WRITE) << 30)
    | (ctypes.sizeof(NsmMessage) << 16)
    | (NSM_IOCTL_MAGIC << 8)
    | NSM_IOCTL_NUMBER
)

_warned = False


def _warn_once(message: str) -> None:
    global _warned
    if not _warned:
        print(f"NSM attestation unavailable: {message}")
        _warned = True


def _nsm_request(fd: int, request: dict) -> dict:
    request_data = cbor2.dumps(request)
    if len(request_data) > NSM_REQUEST_MAX_SIZE:
        raise ValueError("NSM request too large")

    # Keep both buffers referenced until the ioctl has returned
    request_buffer = ctypes.create_string_buffer(request_data, len(request_data))
    response_buffer = (NSM_RESPONSE_MAX_SIZE * ctypes.c_uint8)()

    message = NsmMessage()
    message.request = IoVec(
        ctypes.cast(ctypes.byref(request_buffer), ctypes.c_void_p),
        len(request_buffer),
    )
    message.response = IoVec(
        ctypes.cast(ctypes.byref(response_buffer), ctypes.c_void_p),
        len(response_buffer),
    )

    # The driver fills response_buffer and sets response.iov_len to the CBOR length
    fcntl.ioctl(fd, NSM_IOCTL_REQUEST, message)

    return cbor2.loads(ctypes.string_at(message.response.iov_base, message.response.iov_len))


def get_attestation_document(
    public_key_der: bytes | None,
    nonce: bytes | None,
    user_data: bytes | None,
) -> bytes | None:
    """Return a COSE_Sign1 attestation document, or None if the NSM is unavailable."""
    if not os.path.exists(NSM_DEV_FILE):
        _warn_once(f"{NSM_DEV_FILE} not found (not running in a Nitro Enclave)")
        return None

    try:
        fd = os.open(NSM_DEV_FILE, os.O_RDWR)
        try:
            response = _nsm_request(
                fd,
                {
                    "Attestation": {
                        "user_data": user_data,
                        "nonce": nonce,
                        "public_key": public_key_der,
                    }
                },
            )
        finally:
            os.close(fd)
    except Exception as e:
        _warn_once(f"NSM request failed: {e}")
        return None

    if not isinstance(response, dict) or "Attestation" not in response:
        error = response.get("Error") if isinstance(response, dict) else response
        _warn_once(f"NSM returned an error: {error}")
        return None

    return response["Attestation"]["document"]
