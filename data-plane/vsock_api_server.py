from flask import Flask, request, jsonify
from flask_cors import CORS
from vsock_client import send_request
from Crypto.PublicKey import RSA
import requests
import base64

app = Flask(__name__)
CORS(app)

@app.route("/get_server_pubkey", methods=["GET"]) 
def get_server_pubkey():
    try:
        response = send_request("get_server_pubkey")
        server_pubkey_pem = response["data"]
        pem_str = server_pubkey_pem.decode("utf-8")
        return jsonify({"server_pubkey": pem_str})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/send_encrypted_client_seckey_a", methods=["POST"])
def receive_encrypted_key_a():
    try:
        encrypted_b64 = request.json.get("encrypted_seckey_a")
        encrypted_bytes = base64.b64decode(encrypted_b64)
        response = send_request("send_encrypted_client_seckey_a", encrypted_bytes)
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/send_client_pubkey_b", methods=["POST"])
def receive_pubkey_b():
    try:
        pubkey_b = request.json.get("pubkey_b")
        pubkey_b_bytes = pubkey_b.encode("utf-8")
        response = send_request("send_client_pubkey_b", pubkey_b_bytes)
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/generate_text", methods=["POST"])
def generate_text():
    try:
        data = request.get_json()
        encrypted_b64 = data.get("encrypted_prompt")

        if not encrypted_b64:
            return jsonify({"error": "Missing 'encrypted_prompt'"}), 400

        # Base64 → bytes
        encrypted_prompt_bytes = base64.b64decode(encrypted_b64)

        # Forward to the enclave over vsock
        response = send_request("generate_text", encrypted_prompt_bytes)

        if response.get("status_code") != 0 or "data" not in response:
            return jsonify({"error": "TEE processing failed"}), 500

        # Return raw bytes; the control plane base64-encodes them
        return response["data"]
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)