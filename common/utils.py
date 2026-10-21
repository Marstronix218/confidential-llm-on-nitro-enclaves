import base64
import json
import socket
import struct

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

RSA_KEY_SIZE = 2048
MAX_ENCRYPT_CHUNK_SIZE = (RSA_KEY_SIZE // 8) - 2 * (256 // 8) - 2

# Upper bound for one framed message. Without it a forged 4-byte length prefix
# could make the receiver try to buffer ~4 GB.
MAX_MESSAGE_SIZE = 4 * 1024 * 1024


def send_data(sock: socket.socket, data: bytes):
    data_length = len(data)
    sock.sendall(struct.pack("!I", data_length))
    sock.sendall(data)


def recv_data(sock: socket.socket) -> bytes:
    raw_msglen = recv_all(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack("!I", raw_msglen)[0]
    if msglen > MAX_MESSAGE_SIZE:
        raise ValueError(
            f"Message of {msglen} bytes exceeds MAX_MESSAGE_SIZE ({MAX_MESSAGE_SIZE})"
        )

    return recv_all(sock, msglen)


def recv_all(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


def encrypt_by_chunk(data_to_encrypt: bytes, pubkey: bytes) -> bytes:
    """
    Encrypt arbitrary size of data with RSA and OAEP (padding scheme)

    :param data_to_encrypt: data to be encrypted
    :type data_to_encrypt: bytes, required
    :param pubkey: RSA public key to encrypt the data with
    :type pubkey: bytes, required
    :return: encrypted data appended together
    :rtype: bytes
    """
    public_key = RSA.import_key(pubkey)
    cipher_rsa = PKCS1_OAEP.new(public_key, SHA256)

    result = b""
    for i in range(0, len(data_to_encrypt), MAX_ENCRYPT_CHUNK_SIZE):
        chunk_to_encrypt = data_to_encrypt[i : i + MAX_ENCRYPT_CHUNK_SIZE]
        result += cipher_rsa.encrypt(chunk_to_encrypt)

    return result


def decrypt_by_chunk(data_to_decrypt: bytes, seckey: bytes) -> bytes:
    """
    Decrypt arbitrary size of data with RSA and OAEP

    :param data_to_decrypt: data to be decrypted
    :type data_to_decrypt: bytes, required
    :param seckey: RSA secret key to decrypt data with
    :type seckey: bytes
    :return: decrypted data encoded into bytes sequence using utf-8
    :rtype: bytes
    """
    private_key = RSA.import_key(seckey)
    cipher_rsa = PKCS1_OAEP.new(private_key, SHA256)

    result = b""
    for i in range(0, len(data_to_decrypt), RSA_KEY_SIZE // 8):
        chunk_to_decrypt = data_to_decrypt[i : i + (RSA_KEY_SIZE // 8)]
        result += cipher_rsa.decrypt(chunk_to_decrypt)

    return result


def sign_key_b(pubkey_b: bytes, seckey_a: bytes) -> bytes:
    """
    Build the send_client_pubkey_b payload (encrypt it under key X before sending):
    JSON {"pubkey_b": <PEM str>, "signature": <base64 RSA-PSS/SHA-256 signature over the PEM bytes,
    made with private key A>}. The enclave only accepts key B signed by the session's key A, which the
    host never holds, so the host cannot substitute its own key B.

    :param pubkey_b: public key B (PEM)
    :type pubkey_b: bytes, required
    :param seckey_a: private key A (PEM), the key already sent to the enclave for this session
    :type seckey_a: bytes, required
    :return: UTF-8 JSON payload
    :rtype: bytes
    """
    signature = pss.new(RSA.import_key(seckey_a)).sign(SHA256.new(pubkey_b))
    return json.dumps({
        "pubkey_b": pubkey_b.decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }).encode()
