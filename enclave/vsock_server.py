# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0

import os
import socket
from ast import literal_eval

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from transformers import AutoModelForCausalLM, AutoTokenizer

import utils

PORT = 5000
CONN_TIMEOUT = 128

# "vsock" inside a real Nitro Enclave; "tcp" for the local mock mode (docker compose, no Nitro)
TRANSPORT = os.environ.get("ENCLAVE_TRANSPORT", "vsock")

# Directory produced by download_model.py (tokenizer + weights in one place)
MODEL_DIR = os.environ.get("MODEL_DIR", "/app/model")
MAX_NEW_TOKENS = int(os.environ.get("MAX_NEW_TOKENS", "150"))
SYSTEM_PROMPT = os.environ.get(
    "SYSTEM_PROMPT",
    "You are a helpful assistant running inside a trusted execution environment. Answer concisely.",
)

SERVER_GENERATED_SECKEY = None
CLIENT_GENERATED_SECKEY_A = None
CLIENT_GENERATED_PUBKEY_B = None

# Base-model (GPT-2) generation settings, kept from the original prototype
SEED = 34
MAX_LEN = 100

tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR, local_files_only=True)
model = AutoModelForCausalLM.from_pretrained(MODEL_DIR, local_files_only=True)
if tokenizer.pad_token_id is None:
    tokenizer.pad_token = tokenizer.eos_token

# Instruction-tuned models (Qwen, SmolLM, ...) ship a chat template; base models (GPT-2) do not
IS_CHAT_MODEL = tokenizer.chat_template is not None
print(f"Loaded model from {MODEL_DIR} ({'chat' if IS_CHAT_MODEL else 'base'} model)")


def handle_client(client_socket):
    try:
        message = utils.recv_data(client_socket)

        if not message:
            print("No message received. Closing connection.")
            client_socket.close()
            return

        # Convert the received message to a dictionary
        request = literal_eval(message.decode().rstrip())
        print(f"Received request from client: {request['method']}")

        response = handle_request(request)
        response_str = str(response)

        # Send the response back to the client, followed by a newline delimiter
        utils.send_data(client_socket, response_str.encode())
        # print(f"Data sent back to client: {response}")
        print(f"Sent response to the client")
        print()

    except Exception as e:
        print(f"Error handling client: {e}")

    finally:
        client_socket.close()


def handle_request(request: dict) -> dict:
    response = dict()

    match request["method"]:
        case "get_server_pubkey":
            global SERVER_GENERATED_SECKEY
            key = RSA.generate(utils.RSA_KEY_SIZE)
            SERVER_GENERATED_SECKEY = key.export_key()
            response["status_code"] = 0
            response["data"] = key.publickey().export_key()

        case "send_encrypted_client_seckey_a":
            global CLIENT_GENERATED_SECKEY_A
            encrypted_seckey_a = request["data"]

            CLIENT_GENERATED_SECKEY_A = utils.decrypt_by_chunk(
                encrypted_seckey_a, SERVER_GENERATED_SECKEY
            )

            response["status_code"] = 0
            response["data"] = None

        case "send_client_pubkey_b":
            global CLIENT_GENERATED_PUBKEY_B
            CLIENT_GENERATED_PUBKEY_B = request["data"]

            response["status_code"] = 0
            response["data"] = None

        case "generate_text":
            encrypted_text_prompt = request["data"]

            # Decrypt method returns bytes object, so decode
            # print(f"Received text prompt: {encrypted_text_prompt}")
            decrypted_text_prompt = utils.decrypt_by_chunk(
                encrypted_text_prompt, CLIENT_GENERATED_SECKEY_A
            ).decode()
            print(f"Text prompt: {decrypted_text_prompt}")

            generated_text = generate_text(decrypted_text_prompt)
            print(f"Generated text: {generated_text}")
            encrypted_generated_text = utils.encrypt_by_chunk(
                generated_text.encode(), CLIENT_GENERATED_PUBKEY_B
            )

            response = dict()
            response["status_code"] = 0
            response["data"] = encrypted_generated_text

    return response


def generate_text(text_prompt: str) -> str:
    if IS_CHAT_MODEL:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": text_prompt},
        ]
        chat_text = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        inputs = tokenizer(chat_text, return_tensors="pt")
        output = model.generate(
            **inputs,
            max_new_tokens=MAX_NEW_TOKENS,
            do_sample=True,
            temperature=0.7,
            top_p=0.9,
            pad_token_id=tokenizer.pad_token_id,
        )
        # Return only the newly generated assistant turn
        new_tokens = output[0][inputs["input_ids"].shape[-1]:]
        return tokenizer.decode(new_tokens, skip_special_tokens=True).strip()

    # Base model: plain text continuation (original GPT-2 behaviour)
    encoded_input = tokenizer.encode(text_prompt, return_tensors="pt")
    output = model.generate(
        encoded_input,
        max_length=MAX_LEN,
        do_sample=True,
        num_beams=5,
        no_repeat_ngram_size=2,
        early_stopping=True,
        pad_token_id=tokenizer.pad_token_id,
    )

    return tokenizer.decode(output[0], skip_special_tokens=True)


def main():
    if TRANSPORT == "tcp":
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", PORT))
    else:
        server_socket = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        server_socket.bind((socket.VMADDR_CID_ANY, PORT))

    server_socket.listen(5)

    print(f"Started server on port {PORT} ({TRANSPORT})")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")
        handle_client(client_socket)


if __name__ == "__main__":
    main()
