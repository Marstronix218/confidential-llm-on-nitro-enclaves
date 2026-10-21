"""common/utils.py: chunked RSA-OAEP and length-prefixed framing."""
import math
import os
import socket
import struct
import threading

import pytest

import utils


@pytest.mark.parametrize("size", [0, 1, 190, 191, 4096])
def test_encrypt_decrypt_round_trip_across_chunk_boundaries(client_keys, size):
    assert utils.MAX_ENCRYPT_CHUNK_SIZE == 190  # 2048-bit RSA, OAEP with SHA-256
    plaintext = os.urandom(size)

    ciphertext = utils.encrypt_by_chunk(plaintext, client_keys.pubkey_a)

    assert len(ciphertext) == math.ceil(size / utils.MAX_ENCRYPT_CHUNK_SIZE) * (utils.RSA_KEY_SIZE // 8)
    assert utils.decrypt_by_chunk(ciphertext, client_keys.seckey_a) == plaintext


def test_decrypt_with_wrong_key_fails(client_keys):
    ciphertext = utils.encrypt_by_chunk(b"secret", client_keys.pubkey_a)
    with pytest.raises(ValueError):
        utils.decrypt_by_chunk(ciphertext, client_keys.seckey_b)


@pytest.fixture
def socket_pair():
    a, b = socket.socketpair()
    yield a, b
    a.close()
    b.close()


def test_send_recv_round_trip(socket_pair):
    a, b = socket_pair
    utils.send_data(a, b"hello")
    assert utils.recv_data(b) == b"hello"


def test_recv_data_rejects_frame_over_max_size(socket_pair):
    a, b = socket_pair
    a.sendall(struct.pack("!I", utils.MAX_MESSAGE_SIZE + 1))
    with pytest.raises(ValueError, match="MAX_MESSAGE_SIZE"):
        utils.recv_data(b)


def test_recv_data_accepts_frame_of_exactly_max_size(socket_pair):
    a, b = socket_pair
    assert utils.MAX_MESSAGE_SIZE == 4 * 1024 * 1024
    payload = b"x" * utils.MAX_MESSAGE_SIZE
    sender = threading.Thread(target=utils.send_data, args=(a, payload))
    sender.start()
    received = utils.recv_data(b)
    sender.join()
    assert received == payload


def test_recv_data_truncated_body_returns_none(socket_pair):
    a, b = socket_pair
    a.sendall(struct.pack("!I", 10) + b"abc")
    a.shutdown(socket.SHUT_WR)
    assert utils.recv_data(b) is None


def test_recv_data_truncated_length_prefix_returns_none(socket_pair):
    a, b = socket_pair
    a.sendall(b"\x00\x00")
    a.shutdown(socket.SHUT_WR)
    assert utils.recv_data(b) is None
