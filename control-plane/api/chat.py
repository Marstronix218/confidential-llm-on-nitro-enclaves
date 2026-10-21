import os, re, shutil, secrets, sys, requests, base64, json
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.PublicKey import RSA
# utils.py lives in <repo>/common; the Docker images copy it next to this script instead.
if not os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "utils.py")):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "common"))
from utils import encrypt_by_chunk, decrypt_by_chunk, sign_key_b, RSA_KEY_SIZE
from attestation import verify_attestation
from auth import require_bearer, basic_auth_from_env, bearer_headers_from_env

# Constants
CONTROL_PLANE_HOST = os.environ.get("CONTROL_PLANE_HOST", "http://localhost:5000")   # admin.py (same host)
KEY_DIRECTORY = os.environ.get("KEY_DIRECTORY", os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys"))
TEE_TIMEOUT = int(os.environ.get("TEE_TIMEOUT", "120"))   # seconds; CPU inference inside the enclave can take a while
HTTP_TIMEOUT = 30                                          # seconds; every other outbound request
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "http://localhost:8080").split(",") if o.strip()]

# Attestation: the enclave must prove (Nitro attestation document) that key X belongs to it
REQUIRE_ATTESTATION = os.environ.get("REQUIRE_ATTESTATION", "true").lower() == "true"
ENCLAVE_DEBUG_MODE = os.environ.get("ENCLAVE_DEBUG_MODE", "true").lower() == "true"   # same default as admin.py
DEBUG_PCR = "0" * 96   # --debug-mode enclaves report all-zero SHA-384 PCRs
if ENCLAVE_DEBUG_MODE:
    EXPECTED_PCRS = {0: DEBUG_PCR, 1: DEBUG_PCR, 2: DEBUG_PCR}
else:
    EXPECTED_PCRS = {i: os.environ.get(f"ENCLAVE_PCR{i}", "").strip() for i in range(3)}

ADMIN_AUTH = basic_auth_from_env("ADMIN_USER", "ADMIN_PASSWORD")       # chat.py -> admin.py
DATA_PLANE_HEADERS = bearer_headers_from_env("DATA_PLANE_TOKEN")       # chat.py -> data plane

SESSION_FILE = "session.json"
KEY_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS}})
app.before_request(require_bearer("API_TOKEN", path_prefix="/api/"))

# Set DATA_PLANE_URL directly (local mock mode); otherwise ask admin.py for the data-plane IP on first use
DATA_PLANE_URL = os.environ.get("DATA_PLANE_URL")
_data_plane_url = DATA_PLANE_URL


def data_plane_url():
    global _data_plane_url
    if not _data_plane_url:
        response = requests.get(f"{CONTROL_PLANE_HOST}/api/dataplane/ip", auth=ADMIN_AUTH, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        _data_plane_url = f"http://{response.json()['ip']}:5000"
    return _data_plane_url


def data_plane(method, path, timeout=HTTP_TIMEOUT, **kwargs):
    """Call the data-plane bridge and return its JSON body; raise with its error message on failure."""
    global _data_plane_url
    try:
        response = requests.request(method, f"{data_plane_url()}/{path}",
                                    headers=DATA_PLANE_HEADERS, timeout=timeout, **kwargs)
    except requests.ConnectionError:
        _data_plane_url = DATA_PLANE_URL   # ask admin.py again next time: a restarted instance gets a new IP
        raise
    try:
        body = response.json()
    except ValueError:
        body = {}
    if response.status_code != 200:
        raise RuntimeError(body.get("error") or f"data plane returned HTTP {response.status_code}")
    return body


def key_path(name):
    return os.path.join(KEY_DIRECTORY, name)


def write_key_file(path, data: bytes):
    """Write a key or session file readable by this user only (0o600)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def remove_server_key():
    """Forget the stored key X and enclave session."""
    for name in ("server_key.bin", SESSION_FILE):
        if os.path.exists(key_path(name)):
            os.remove(key_path(name))


def read_session_id():
    with open(key_path(SESSION_FILE)) as f:
        return json.load(f)["session_id"]


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})


@app.route('/api/create_key_directory', methods=['GET'])
def create_key_directory():
    """Create a key directory for storing RSA keys."""
    try:
        if not os.path.exists(KEY_DIRECTORY):
            os.mkdir(KEY_DIRECTORY)
        # An existing directory can still be unusable (e.g. a root-owned volume, chat.py runs as uid 10001)
        if not os.access(KEY_DIRECTORY, os.W_OK | os.X_OK):
            return jsonify({
                "status": "error",
                "message": f"Key directory {KEY_DIRECTORY} is not writable by this process."
            }), 500
        return jsonify({
            "status": "success",
            "message": f"Key directory created at {KEY_DIRECTORY}."
        })
    except OSError as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to create directory: {str(e)}"
        }), 500


@app.route('/api/retrieve_server_key', methods=['GET'])
def api_get_server_key():
    """Fetch enclave key X with a fresh nonce, verify its attestation, then store it."""
    if not os.path.exists(KEY_DIRECTORY):
        return jsonify({"status": "error", "message": "Create the key directory first."}), 400

    try:
        remove_server_key()   # never fall back to a previous session's key X, whatever happens below
        nonce = secrets.token_bytes(32)
        body = data_plane("GET", "get_server_pubkey",
                          params={"nonce": base64.urlsafe_b64encode(nonce).decode()})
        session_id = body["session_id"]
        server_pubkey = RSA.import_key(body["server_pubkey"])
        attestation_b64 = body.get("attestation")

        result = None
        chain_valid = False   # signature, certificate chain to the AWS root, nonce and key X all check out
        if attestation_b64:
            doc = base64.b64decode(attestation_b64)
            key_der = server_pubkey.export_key(format="DER")   # SubjectPublicKeyInfo
            result = verify_attestation(doc, expected_nonce=nonce, expected_public_key_der=key_der,
                                        expected_pcrs=EXPECTED_PCRS)
            # Same checks without the PCR comparison
            chain_valid = verify_attestation(doc, expected_nonce=nonce, expected_public_key_der=key_der,
                                             expected_pcrs={}).verified
            if not ENCLAVE_DEBUG_MODE:
                missing = [f"ENCLAVE_PCR{i}" for i, v in EXPECTED_PCRS.items() if not v]
                if missing:
                    result.errors.append(f"expected PCRs not configured: {', '.join(missing)}")
                    result.verified = False

        # document_ok: valid and its PCRs match what we expect (all zero for a debug-mode enclave).
        # verified: additionally, the PCRs are real measurements, so the image running is the one we built.
        document_ok = bool(result and result.verified)
        verified = document_ok and not ENCLAVE_DEBUG_MODE
        if REQUIRE_ATTESTATION and not document_ok:
            reason = "; ".join(result.errors) if result else "the enclave returned no attestation document"
            return jsonify({
                "status": "error",
                "message": f"Attestation verification failed, server key NOT stored: {reason}"
            }), 502

        if result is None:
            mode = "skipped"     # no document (local mock), REQUIRE_ATTESTATION=false
        elif not document_ok:
            mode = "failed"      # document checked and invalid, REQUIRE_ATTESTATION=false
        else:
            mode = "debug" if ENCLAVE_DEBUG_MODE else "verified"

        pcrs = result.pcrs if result else {}
        attestation = {
            "verified": verified,
            "chain_valid": chain_valid,
            "pcr0": pcrs.get(0), "pcr1": pcrs.get(1), "pcr2": pcrs.get(2),
            "mode": mode,
        }
        if result and not document_ok:
            attestation["errors"] = result.errors

        write_key_file(key_path("server_key.bin"), server_pubkey.export_key())
        write_key_file(key_path(SESSION_FILE), json.dumps({
            "session_id": session_id, "attestation_verified": verified, "chain_valid": chain_valid,
            "attestation_mode": mode, "pcrs": {str(i): v for i, v in pcrs.items()}}).encode())

        return jsonify({
            "status": "success",
            "message": "Server public key retrieved and saved to server_key.bin.",
            "attestation": attestation
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to retrieve server key: {str(e)}"
        }), 500

@app.route('/api/generate_key', methods=['POST'])
def generate_key():
    """Generate a new RSA key pair."""
    try:
        data = request.json
        key_name = data.get('key_name')

        if not key_name or not KEY_NAME_RE.match(key_name):
            return jsonify({
                "status": "error",
                "message": "Key name is required (letters, digits, '_' and '-' only)."
            }), 400

        key = RSA.generate(RSA_KEY_SIZE)
        write_key_file(os.path.join(KEY_DIRECTORY, f"{key_name}_private.pem"), key.export_key())
        write_key_file(os.path.join(KEY_DIRECTORY, f"{key_name}_public.pem"), key.publickey().export_key())

        return jsonify({
            "status": "success",
            "message": f"Key {key_name} generated and saved."
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to generate key: {str(e)}"
        }), 500

@app.route('/api/encrypt_key_a', methods=['GET'])
def encrypt_key_a():
    """Encrypt key A using the server's public key."""
    try:
        private_key_path = os.path.join(KEY_DIRECTORY, "key_a_private.pem")
        server_key_path = os.path.join(KEY_DIRECTORY, "server_key.bin")

        if not os.path.exists(private_key_path) or not os.path.exists(server_key_path):
            return jsonify({
                "status": "error",
                "message": "Key A private key or server key not found."
            }), 404

        with open(private_key_path, "rb") as pk_file:
            private_key = pk_file.read()

        with open(server_key_path, "rb") as sk_file:
            server_key = sk_file.read()

        encrypted_key_a = encrypt_by_chunk(private_key, server_key)

        # Save the encrypted key for later use
        write_key_file(os.path.join(KEY_DIRECTORY, "key_a_encrypted.bin"), encrypted_key_a)

        return jsonify({
            "status": "success",
            "message": "Key A (private key) encrypted successfully."
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to encrypt Key A: {str(e)}"
        }), 500

@app.route('/api/send_encrypted_key_a', methods=['GET'])
def send_encrypted_key_a():
    """Send the encrypted Key A to the TEE (Data Plane) via POST."""
    try:
        encrypted_key_path = os.path.join(KEY_DIRECTORY, "key_a_encrypted.bin")

        if not os.path.exists(encrypted_key_path) or not os.path.exists(key_path(SESSION_FILE)):
            return jsonify({
                "status": "error",
                "message": "Encrypted Key A or enclave session not found."
            }), 404

        with open(encrypted_key_path, "rb") as pk_file:
            encrypted_key_bytes = pk_file.read()
            encrypted_key_b64 = base64.b64encode(encrypted_key_bytes).decode("utf-8")

        # Send to TEE
        tee_response = data_plane("POST", "send_encrypted_client_seckey_a",
                                  json={"session_id": read_session_id(), "encrypted_seckey_a": encrypted_key_b64})

        return jsonify({
            "status": "success",
            "message": "Encrypted Key A sent to the TEE successfully.",
            "tee_response": tee_response
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to send encrypted Key A: {str(e)}"
        }), 500


@app.route('/api/send_public_key_b', methods=['GET'])
def send_public_key_b():
    """Send Key B (public), signed with Key A and encrypted under enclave key X, to the TEE (Data Plane)."""
    try:
        public_key_b_path = os.path.join(KEY_DIRECTORY, "key_b_public.pem")
        private_key_a_path = os.path.join(KEY_DIRECTORY, "key_a_private.pem")
        server_key_path = os.path.join(KEY_DIRECTORY, "server_key.bin")

        if not all(os.path.exists(p) for p in (public_key_b_path, private_key_a_path, server_key_path,
                                                key_path(SESSION_FILE))):
            return jsonify({
                "status": "error",
                "message": "Key B public key, Key A private key, server key or enclave session not found."
            }), 404

        with open(public_key_b_path, "rb") as pk_file:
            public_key_b = pk_file.read()
        with open(private_key_a_path, "rb") as ak_file:
            private_key_a = ak_file.read()
        with open(server_key_path, "rb") as sk_file:
            server_key = sk_file.read()

        # Encrypted so the host cannot read it, signed with A so the host cannot swap in its own key B
        payload = sign_key_b(public_key_b, private_key_a)
        encrypted_b64 = base64.b64encode(encrypt_by_chunk(payload, server_key)).decode("utf-8")

        # Send to TEE
        tee_response = data_plane("POST", "send_client_pubkey_b",
                                  json={"session_id": read_session_id(), "encrypted_pubkey_b": encrypted_b64})

        return jsonify({
            "status": "success",
            "message": "Key B (public) sent to the TEE successfully.",
            "tee_response": tee_response
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to send Key B public key: {str(e)}"
        }), 500

@app.route('/api/delete_key', methods=['POST'])
def delete_key():
    """Delete a specific key."""
    try:
        data = request.json
        key_name = data.get('key_name')

        if not key_name or not KEY_NAME_RE.match(key_name):
            return jsonify({
                "status": "error",
                "message": "Key name is required (letters, digits, '_' and '-' only)."
            }), 400

        private_key_path = os.path.join(KEY_DIRECTORY, f"{key_name}_private.pem")

        files_deleted = 0

        if os.path.exists(private_key_path):
            os.remove(private_key_path)
            files_deleted += 1

        if files_deleted == 0:
            return jsonify({
                "status": "error",
                "message": f"No keys found for {key_name}."
            }), 404

        return jsonify({
            "status": "success",
            "message": f"Deleted {files_deleted} files for key {key_name}."
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to delete key: {str(e)}"
        }), 500

@app.route('/api/delete_all_keys', methods=['GET'])
def delete_all_keys():
    """Delete all keys."""
    try:
        if os.path.exists(KEY_DIRECTORY):
            shutil.rmtree(KEY_DIRECTORY)

        return jsonify({
            "status": "success",
            "message": "All keys deleted successfully."
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to delete all keys: {str(e)}"
        }), 500


def parse_messages(data):
    """{"messages": [...]} (preferred) or {"prompt": str} -> validated message list, or None."""
    messages = data.get('messages')
    if messages is None and isinstance(data.get('prompt'), str) and data['prompt']:
        messages = [{"role": "user", "content": data['prompt']}]
    if not isinstance(messages, list) or not messages:
        return None
    for m in messages:
        if (not isinstance(m, dict) or m.get("role") not in ("user", "assistant")
                or not isinstance(m.get("content"), str)):
            return None
    if messages[-1]["role"] != "user" or not messages[-1]["content"]:
        return None
    return [{"role": m["role"], "content": m["content"]} for m in messages]


@app.route('/api/encrypt_prompt', methods=['POST'])
def encrypt_prompt():
    """Encrypt the conversation ({"messages": [...]} JSON) using Key A public key."""
    try:
        messages = parse_messages(request.get_json(silent=True) or {})

        if messages is None:
            return jsonify({
                "status": "error",
                "message": "messages (role user/assistant, ending with a user message) or prompt is required."
            }), 400

        key_a_public_path = os.path.join(KEY_DIRECTORY, "key_a_public.pem")

        if not os.path.exists(key_a_public_path):
            return jsonify({
                "status": "error",
                "message": "Key A public key not found."
            }), 404

        with open(key_a_public_path, "rb") as f:
            key_a_public = f.read()

        # Encrypt to bytes
        payload = json.dumps({"messages": messages}).encode("utf-8")
        encrypted_prompt = encrypt_by_chunk(payload, key_a_public)
        encrypted_b64 = base64.b64encode(encrypted_prompt).decode("utf-8")

        return jsonify({
            "status": "success",
            "encrypted_prompt": encrypted_b64
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to encrypt prompt: {str(e)}"
        }), 500

@app.route('/api/generate_text', methods=['POST'])
def generate_text():
    """Forward encrypted prompt to Data Plane to process via TEE."""
    try:
        data = request.get_json(silent=True) or {}
        encrypted_prompt = data.get('encrypted_prompt')

        if not encrypted_prompt:
            return jsonify({
                "status": "error",
                "message": "Encrypted prompt is required."
            }), 400
        if not os.path.exists(key_path(SESSION_FILE)):
            return jsonify({
                "status": "error",
                "message": "No enclave session: retrieve the server key first."
            }), 404

        # Forward to the data plane
        body = data_plane("POST", "generate_text", timeout=TEE_TIMEOUT,
                          json={"session_id": read_session_id(), "encrypted_prompt": encrypted_prompt})

        return jsonify({
            "status": "success",
            "encrypted_response": body["encrypted_response"]
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to communicate with TEE: {str(e)}"
        }), 500

@app.route('/api/decrypt_response', methods=['POST'])
def decrypt_response():
    """Decrypt the response (base64 ciphertext) using Key B private key."""
    try:
        data = request.get_json(silent=True) or {}
        encrypted_b64 = data.get('encrypted_response')

        if not encrypted_b64:
            return jsonify({
                "status": "error",
                "message": "Encrypted response is required."
            }), 400

        cipher_bytes = base64.b64decode(encrypted_b64)

        key_b_private_path = os.path.join(KEY_DIRECTORY, "key_b_private.pem")

        if not os.path.exists(key_b_private_path):
            return jsonify({
                "status": "error",
                "message": "Key B private key not found."
            }), 404

        with open(key_b_private_path, "rb") as f:
            key_b_private = f.read()

        decrypted_response = decrypt_by_chunk(cipher_bytes, key_b_private).decode("utf-8")

        return jsonify({
            "status": "success",
            "decrypted_response": decrypted_response
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to decrypt response: {str(e)}"
        }), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=8501)
