# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0

#!/usr/local/bin/env python3
import json
import os
import secrets
import socket
import subprocess
import sys
from ast import literal_eval

from Crypto.PublicKey import RSA

# utils.py lives in <repo>/common; the Docker images copy it next to this script instead.
if not os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "utils.py")):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))

import utils

PORT = 5000
CONN_TIMEOUT = 256

# "vsock" on a real Nitro parent instance; "tcp" for the local mock mode (docker compose)
TRANSPORT = os.environ.get("ENCLAVE_TRANSPORT", "vsock")
ENCLAVE_HOST = os.environ.get("ENCLAVE_HOST", "localhost")


def connect_to_server() -> socket.socket:
    """
    Establish vsock connection to the server inside the enclave

    :return: socket connection if successful; otherwise, returns None
    :rtype: socket.socket or None
    """
    try:
        if TRANSPORT == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(CONN_TIMEOUT)
            sock.connect((ENCLAVE_HOST, PORT))
        else:
            sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            sock.settimeout(CONN_TIMEOUT)
            sock.connect((get_cid(), PORT))
        return sock

    except Exception as e:
        print(f"Error while connecting to server: {e}")
        return None


def get_cid() -> str:
    """
    Get context identifier for the currently running enclave

    :return: string representing cid
    :rtype: str
    """
    proc = subprocess.Popen(
        ["/bin/nitro-cli", "describe-enclaves"], stdout=subprocess.PIPE
    )
    output = json.loads(proc.communicate()[0].decode())
    enclave_cid = output[0]["EnclaveCID"]
    return enclave_cid


def send_request(method: str, data=b"", session_id=None) -> dict:
    """
    Send request to the server
    There are four types of requests in this program.
    1. get_server_pubkey (data: optional nonce; creates a session)
    2. send_encrypted_client_seckey_a
    3. send_client_pubkey_b
    4. generate_text

    :param method: string representing what type of request to send
    :type method: str, required
    :param data: content of the request
    :type data: bytes, default to b""
    :param session_id: session returned by get_server_pubkey (methods 2-4)
    :type session_id: str or None
    :return: dictionary representing response from the server:
        {"status_code": 0, "data": ...} or {"status_code": 1, "error": str}
    :rtype: dict
    """
    request = dict()
    request["method"] = method
    if session_id is not None:
        request["session_id"] = session_id
    request["data"] = data
    encoded_request = str(request).encode()

    client_sock = connect_to_server()
    if client_sock is None:
        raise ConnectionError("Could not connect to the enclave")

    try:
        # Sends request and receives response
        utils.send_data(client_sock, encoded_request)
        response = utils.recv_data(client_sock)
    finally:
        client_sock.close()

    if response is None:
        raise ConnectionError("Enclave closed the connection without a response")

    return literal_eval(response.decode().rstrip())


def _check(response: dict) -> dict:
    if response.get("status_code") != 0:
        raise RuntimeError(f"Enclave error: {response.get('error')}")
    return response


def test():
    nonce = secrets.token_bytes(32)
    session = _check(send_request("get_server_pubkey", nonce))["data"]
    session_id = session["session_id"]
    server_pubkey = session["pubkey"]
    attestation = session["attestation"]
    print(f"session_id: {session_id}")
    print(
        f"attestation document: {len(attestation)} bytes"
        if attestation
        else "attestation document: none (not running in a Nitro Enclave?)"
    )

    # generate pubkey_a and seckey_a, then encrypt it with pubkey_x
    key_a = RSA.generate(utils.RSA_KEY_SIZE)
    seckey_a = key_a.export_key()
    pubkey_a = key_a.publickey().export_key()

    encrypted_seckey_a = utils.encrypt_by_chunk(seckey_a, server_pubkey)
    _check(send_request("send_encrypted_client_seckey_a", encrypted_seckey_a, session_id))

    # generate seckey_b and pubkey_b, sign pubkey_b with seckey_a, then encrypt both with pubkey_x
    key_b = RSA.generate(utils.RSA_KEY_SIZE)
    seckey_b = key_b.export_key()
    pubkey_b = key_b.publickey().export_key()

    encrypted_pubkey_b = utils.encrypt_by_chunk(utils.sign_key_b(pubkey_b, seckey_a), server_pubkey)
    _check(send_request("send_client_pubkey_b", encrypted_pubkey_b, session_id))

    text_prompt = "Hello."
    print(f"text prompt: {text_prompt}")
    payload = json.dumps({"messages": [{"role": "user", "content": text_prompt}]})
    encrypted_text_prompt = utils.encrypt_by_chunk(payload.encode(), pubkey_a)

    response = _check(send_request("generate_text", encrypted_text_prompt, session_id))
    encrypted_generated_text = response["data"]
    decrypted_generated_text = utils.decrypt_by_chunk(
        encrypted_generated_text, seckey_b
    ).decode()
    print(f"decrypted generated_text: {decrypted_generated_text}")


if __name__ == "__main__":
    test()
