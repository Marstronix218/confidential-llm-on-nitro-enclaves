# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0

#!/usr/local/bin/env python3
import argparse
import json
import os
import socket
import struct
import subprocess
from ast import literal_eval

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

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


def send_request(method: str, data=b"") -> dict:
    """
    Send request to the server
    There are four types of requests in this program.
    1. get_server_pubkey
    2. send_encrypted_client_seckey_a
    3. send_client_pubkey_b
    4. generate_text

    :param method: string representing what type of request to send
    :type method: str, required
    :param data: content of the request
    :type data: bytes, default to b""
    :return: dictionary representing response from the server.
        The response will have two fields: status_code and data.
    :rtype: dict
    """
    request = dict()
    request["method"] = method
    request["data"] = data
    encoded_request = str(request).encode()

    client_sock = connect_to_server()
    # Sends request and receives response
    utils.send_data(client_sock, encoded_request)

    response = utils.recv_data(client_sock).decode().rstrip()
    client_sock.close()

    return literal_eval(response)


def test():
    server_pubkey = send_request("get_server_pubkey")["data"]

    # generate pubkey_a and seckey_a, then encrypt it with pubkey_x
    key_a = RSA.generate(utils.RSA_KEY_SIZE)
    seckey_a = key_a.export_key()
    pubkey_a = key_a.publickey().export_key()

    encrypted_seckey_a = utils.encrypt_by_chunk(seckey_a, server_pubkey)
    send_request("send_encrypted_client_seckey_a", encrypted_seckey_a)

    # generate seckey_b and pubkey_b
    key_b = RSA.generate(utils.RSA_KEY_SIZE)
    seckey_b = key_b.export_key()
    pubkey_b = key_b.publickey().export_key()

    send_request("send_client_pubkey_b", pubkey_b)

    text_prompt = "Hello."
    print(f"text prompt: {text_prompt}")
    encrypted_text_prompt = utils.encrypt_by_chunk(text_prompt.encode(), pubkey_a)

    response = send_request("generate_text", encrypted_text_prompt)
    encrypted_generated_text = response["data"]
    decrypted_generated_text = utils.decrypt_by_chunk(
        encrypted_generated_text, seckey_b
    ).decode()
    print(f"decrypted generated_text: {decrypted_generated_text}")


if __name__ == "__main__":
    test()
