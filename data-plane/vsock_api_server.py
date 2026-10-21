"""HTTP -> vsock bridge on the parent instance. Stateless: it only relays
ciphertext, session ids and attestation documents between chat.py and the enclave."""

import base64
import binascii
import hmac
import os

from flask import Flask, request, jsonify

from vsock_client import send_request

MAX_NONCE_SIZE = 64

# Optional shared secret with chat.py: every route except /health then
# requires "Authorization: Bearer <DATA_PLANE_TOKEN>".
DATA_PLANE_TOKEN = os.environ.get("DATA_PLANE_TOKEN") or None

app = Flask(__name__)


class BadRequest(Exception):
    """Invalid client input -> HTTP 400."""


class EnclaveError(Exception):
    """The enclave answered with status_code 1 or was unreachable -> HTTP 502."""


@app.errorhandler(BadRequest)
def handle_bad_request(e):
    return jsonify({"error": str(e)}), 400


@app.errorhandler(EnclaveError)
def handle_enclave_error(e):
    return jsonify({"error": str(e)}), 502


@app.before_request
def check_auth():
    if DATA_PLANE_TOKEN is None or request.path == "/health":
        return None
    supplied = request.headers.get("Authorization", "").encode()
    expected = f"Bearer {DATA_PLANE_TOKEN}".encode()
    if not hmac.compare_digest(supplied, expected):
        return jsonify({"error": "Unauthorized"}), 401
    return None


def decode_b64(value: str, field: str) -> bytes:
    """Decode standard or URL-safe base64, with or without padding."""
    if not isinstance(value, str):
        raise BadRequest(f"'{field}' must be a base64 string")
    value = value.strip().replace("-", "+").replace("_", "/")
    value += "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise BadRequest(f"'{field}' is not valid base64") from None


def json_body() -> dict:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise BadRequest("Request body must be a JSON object")
    return body


def session_id_from(body: dict) -> str:
    session_id = body.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise BadRequest("Missing 'session_id'")
    return session_id


def b64_field(body: dict, field: str) -> bytes:
    if not body.get(field):
        raise BadRequest(f"Missing '{field}'")
    return decode_b64(body[field], field)


def call_enclave(method: str, data: bytes = b"", session_id=None) -> dict:
    try:
        response = send_request(method, data, session_id)
    except Exception as e:
        raise EnclaveError(f"Enclave unreachable: {e}") from None
    if not isinstance(response, dict) or response.get("status_code") != 0:
        error = response.get("error") if isinstance(response, dict) else None
        raise EnclaveError(error or "TEE processing failed")
    return response


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/get_server_pubkey", methods=["GET"])
def get_server_pubkey():
    nonce = b""
    if request.args.get("nonce"):
        nonce = decode_b64(request.args["nonce"], "nonce")
        if len(nonce) > MAX_NONCE_SIZE:
            raise BadRequest(f"'nonce' must be at most {MAX_NONCE_SIZE} bytes")

    data = call_enclave("get_server_pubkey", nonce)["data"]
    attestation = data.get("attestation")
    return jsonify(
        {
            "session_id": data["session_id"],
            "server_pubkey": data["pubkey"].decode("utf-8"),
            "attestation": base64.b64encode(attestation).decode("ascii")
            if attestation
            else None,
        }
    )


@app.route("/send_encrypted_client_seckey_a", methods=["POST"])
def receive_encrypted_key_a():
    body = json_body()
    session_id = session_id_from(body)
    encrypted_seckey_a = b64_field(body, "encrypted_seckey_a")
    call_enclave("send_encrypted_client_seckey_a", encrypted_seckey_a, session_id)
    return jsonify({"status_code": 0})


@app.route("/send_client_pubkey_b", methods=["POST"])
def receive_pubkey_b():
    body = json_body()
    session_id = session_id_from(body)
    encrypted_pubkey_b = b64_field(body, "encrypted_pubkey_b")
    call_enclave("send_client_pubkey_b", encrypted_pubkey_b, session_id)
    return jsonify({"status_code": 0})


@app.route("/generate_text", methods=["POST"])
def generate_text():
    body = json_body()
    session_id = session_id_from(body)
    encrypted_prompt = b64_field(body, "encrypted_prompt")
    response = call_enclave("generate_text", encrypted_prompt, session_id)
    return jsonify(
        {"encrypted_response": base64.b64encode(response["data"]).decode("ascii")}
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
