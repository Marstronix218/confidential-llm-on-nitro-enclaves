# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0

import base64
import json
import os
import secrets
import socket
import sys
import time
from ast import literal_eval
from dataclasses import dataclass

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from transformers import AutoModelForCausalLM, AutoTokenizer

# utils.py lives in <repo>/common; the Docker images copy it next to this script instead.
if not os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "utils.py")):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))

import nsm
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

# Prompts and answers are only printed when explicitly enabled (local demo).
# The real enclave must never log plaintext.
LOG_PLAINTEXT = os.environ.get("ENCLAVE_LOG_PLAINTEXT", "false").strip().lower() == "true"

MAX_SESSIONS = 32
# Sliding expiry: a session is dropped after SESSION_TTL_SECONDS without any request (last_used is
# refreshed by every request that names it). When MAX_SESSIONS is reached the oldest-created one goes.
SESSION_TTL_SECONDS = 3600
MAX_NONCE_SIZE = 64


@dataclass
class Session:
    session_id: str
    seckey_x: bytes  # enclave key pair X (PEM, private)
    pubkey_x: bytes  # PEM, public
    created_at: float
    last_used: float
    # Both client keys are write-once per session: a host cannot replace them after the client sent them
    seckey_a: bytes | None = None  # client private key A (PEM), decrypts prompts
    pubkey_b: bytes | None = None  # client public key B (PEM, signed with A), encrypts answers


SESSIONS: dict[str, Session] = {}


class RequestError(Exception):
    """A client error whose message is returned to the caller as-is."""


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
        client_socket.settimeout(CONN_TIMEOUT)
        try:
            message = utils.recv_data(client_socket)
        except ValueError as e:
            # Oversized frame: answer with an error instead of reading it
            send_response(client_socket, error_response(str(e)))
            return

        if not message:
            print("No message received. Closing connection.")
            return

        try:
            # Convert the received message to a dictionary
            request = literal_eval(message.decode().rstrip())
        except Exception:
            send_response(client_socket, error_response("Malformed request"))
            return

        if not isinstance(request, dict):
            send_response(client_socket, error_response("Request must be a dict"))
            return

        print(f"Received request from client: {request.get('method')}")
        send_response(client_socket, handle_request(request))
        print("Sent response to the client")
        print()

    except Exception as e:
        print(f"Error handling client: {e}")

    finally:
        client_socket.close()


def send_response(client_socket, response: dict):
    utils.send_data(client_socket, str(response).encode())


def error_response(message: str) -> dict:
    return {"status_code": 1, "error": message}


def handle_request(request: dict) -> dict:
    method = request.get("method")
    try:
        match method:
            case "get_server_pubkey":
                return {"status_code": 0, "data": create_session(request.get("data", b""))}

            case "send_encrypted_client_seckey_a":
                session = get_session(request)
                if session.seckey_a is not None:
                    raise RequestError("Key A already set for this session")
                seckey_a = utils.decrypt_by_chunk(
                    request_bytes(request), session.seckey_x
                )
                if not RSA.import_key(seckey_a).has_private():
                    raise RequestError("Key A must be a private key")
                session.seckey_a = seckey_a
                return {"status_code": 0, "data": None}

            case "send_client_pubkey_b":
                session = get_session(request)
                if session.pubkey_b is not None:
                    raise RequestError("Key B already set for this session")
                if session.seckey_a is None:
                    raise RequestError("Key A must be set before key B")
                # Encrypted under X and signed with key A, so the host can neither read nor swap key B
                payload = utils.decrypt_by_chunk(request_bytes(request), session.seckey_x)
                session.pubkey_b = verify_key_b(payload, session.seckey_a)
                return {"status_code": 0, "data": None}

            case "generate_text":
                session = get_session(request)
                if session.seckey_a is None or session.pubkey_b is None:
                    raise RequestError("Keys A and B must be set before generate_text")

                decrypted_payload = utils.decrypt_by_chunk(
                    request_bytes(request), session.seckey_a
                )
                try:
                    decrypted_payload = decrypted_payload.decode()
                except UnicodeDecodeError:
                    # Re-raised without the original message, which quotes plaintext bytes
                    raise RequestError("Prompt is not valid UTF-8") from None

                generated_text = generate_text(decrypted_payload)
                if LOG_PLAINTEXT:
                    print(f"Generated text: {generated_text}")
                encrypted_generated_text = utils.encrypt_by_chunk(
                    generated_text.encode(), session.pubkey_b
                )
                return {"status_code": 0, "data": encrypted_generated_text}

            case _:
                raise RequestError(f"Unknown method: {method!r}")

    except RequestError as e:
        print(f"Rejected {method!r}: {e}")
        return error_response(str(e))
    except Exception as e:
        # Exception texts can quote decrypted data, so only the type leaves the enclave by default
        detail = f"{type(e).__name__}: {e}" if LOG_PLAINTEXT else type(e).__name__
        print(f"Failed {method!r}: {detail}")
        return error_response(f"{method} failed: {detail}")


def request_bytes(request: dict) -> bytes:
    data = request.get("data")
    if not isinstance(data, bytes) or not data:
        raise RequestError("'data' must be non-empty bytes")
    return data


def verify_key_b(payload: bytes, seckey_a: bytes) -> bytes:
    """Check a utils.sign_key_b payload against the session's key A; return public key B (PEM)."""
    try:
        parsed = json.loads(payload)
        pubkey_b = parsed["pubkey_b"].encode("ascii")
        signature = base64.b64decode(parsed["signature"], validate=True)
    except (ValueError, KeyError, TypeError, AttributeError):
        raise RequestError("Key B must be JSON {pubkey_b, signature}") from None
    try:
        RSA.import_key(pubkey_b)
    except (ValueError, IndexError, TypeError):
        raise RequestError("pubkey_b is not an RSA key") from None
    try:
        pss.new(RSA.import_key(seckey_a).publickey()).verify(SHA256.new(pubkey_b), signature)
    except (ValueError, TypeError):
        raise RequestError("Key B signature does not verify with key A") from None
    return pubkey_b


def evict_expired_sessions(now: float):
    for session_id in [
        sid for sid, s in SESSIONS.items() if now - s.last_used > SESSION_TTL_SECONDS
    ]:
        del SESSIONS[session_id]


def create_session(nonce) -> dict:
    if nonce is None:
        nonce = b""
    if not isinstance(nonce, bytes) or len(nonce) > MAX_NONCE_SIZE:
        raise RequestError(f"Nonce must be at most {MAX_NONCE_SIZE} bytes")

    now = time.monotonic()
    evict_expired_sessions(now)
    while len(SESSIONS) >= MAX_SESSIONS:
        oldest = min(SESSIONS.values(), key=lambda s: s.last_used)
        del SESSIONS[oldest.session_id]

    key = RSA.generate(utils.RSA_KEY_SIZE)
    session = Session(
        session_id=secrets.token_urlsafe(16),
        seckey_x=key.export_key(),
        pubkey_x=key.publickey().export_key(),
        created_at=now,
        last_used=now,
    )
    SESSIONS[session.session_id] = session

    # Binds public key X (DER SubjectPublicKeyInfo) and the client's nonce to the
    # enclave's measurements. None outside a real Nitro Enclave.
    attestation = nsm.get_attestation_document(
        public_key_der=key.publickey().export_key(format="DER"),
        nonce=nonce or None,
        user_data=None,
    )
    print(f"Created session ({len(SESSIONS)} active)")

    return {
        "session_id": session.session_id,
        "pubkey": session.pubkey_x,
        "attestation": attestation,
    }


def get_session(request: dict) -> Session:
    session_id = request.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise RequestError("Missing session_id")

    now = time.monotonic()
    session = SESSIONS.get(session_id)
    if session is not None and now - session.last_used > SESSION_TTL_SECONDS:
        del SESSIONS[session_id]
        session = None
    if session is None:
        raise RequestError("Unknown or expired session_id")
    session.last_used = now
    return session


def parse_messages(payload: str) -> list[dict]:
    """
    Accept {"messages": [{"role", "content"}, ...]} or, for backwards
    compatibility, a plain prompt string (a single user message). A payload that
    starts with "{" must be that JSON object; it is never treated as a plain prompt.
    """
    if not payload.lstrip().startswith("{"):
        return [{"role": "user", "content": payload}]
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        raise RequestError("Prompt starts with '{' but is not valid JSON") from None
    if not isinstance(parsed, dict) or "messages" not in parsed:
        raise RequestError("JSON prompt must be an object with 'messages'")

    messages = parsed["messages"]
    if not isinstance(messages, list) or not messages:
        raise RequestError("'messages' must be a non-empty list")
    for message in messages:
        if (
            not isinstance(message, dict)
            or message.get("role") not in ("user", "assistant")
            or not isinstance(message.get("content"), str)
        ):
            raise RequestError(
                "Each message needs role 'user' or 'assistant' and string content"
            )
    if messages[-1]["role"] != "user":
        raise RequestError("The last message must be from the user")

    return [{"role": m["role"], "content": m["content"]} for m in messages]


def generate_text(payload: str) -> str:
    messages = parse_messages(payload)
    if LOG_PLAINTEXT:
        print(f"Text prompt: {messages[-1]['content']} ({len(messages)} message(s))")

    if IS_CHAT_MODEL:
        messages = [{"role": "system", "content": SYSTEM_PROMPT}] + messages
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

    # Base model: plain text continuation of the last user message (original GPT-2 behaviour)
    text_prompt = messages[-1]["content"]
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
        try:
            client_socket, addr = server_socket.accept()
        except OSError as e:
            print(f"Error accepting connection: {e}")
            continue
        print(f"Accepted connection from {addr}")
        handle_client(client_socket)


if __name__ == "__main__":
    main()
