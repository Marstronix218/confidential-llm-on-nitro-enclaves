"""data-plane/vsock_api_server.py (HTTP -> vsock bridge) with the enclave call monkeypatched."""
import base64
import types

import pytest

import vsock_api_server as bridge

TOKEN = "test-data-plane-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
PEM = b"-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----"


@pytest.fixture
def enclave_calls(monkeypatch):
    """Replace send_request; records (method, data, session_id) and answers from `responses`."""
    calls = []
    responses = {
        "get_server_pubkey": {"status_code": 0, "data": {
            "session_id": "sid-1", "pubkey": PEM, "attestation": b"\x84COSE"}},
        "send_encrypted_client_seckey_a": {"status_code": 0, "data": None},
        "send_client_pubkey_b": {"status_code": 0, "data": None},
        "generate_text": {"status_code": 0, "data": b"\x00\x01ciphertext"},
    }

    def send_request(method, data=b"", session_id=None):
        calls.append((method, data, session_id))
        return responses[method]

    monkeypatch.setattr(bridge, "send_request", send_request)
    monkeypatch.setattr(bridge, "DATA_PLANE_TOKEN", TOKEN)
    return types.SimpleNamespace(calls=calls, responses=responses)


@pytest.fixture
def client():
    return bridge.app.test_client()


def test_health_needs_no_auth(client, enclave_calls):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}, {"Authorization": TOKEN}])
def test_unauthorized(client, enclave_calls, headers):
    assert client.get("/get_server_pubkey", headers=headers).status_code == 401
    assert client.post("/generate_text", headers=headers, json={}).status_code == 401
    assert enclave_calls.calls == []


def test_no_token_configured_means_no_auth(client, enclave_calls, monkeypatch):
    monkeypatch.setattr(bridge, "DATA_PLANE_TOKEN", None)
    assert client.get("/get_server_pubkey").status_code == 200


def test_get_server_pubkey(client, enclave_calls):
    response = client.get("/get_server_pubkey", headers=AUTH)
    assert response.status_code == 200
    assert response.get_json() == {
        "session_id": "sid-1",
        "server_pubkey": PEM.decode(),
        "attestation": base64.b64encode(b"\x84COSE").decode(),
    }
    assert enclave_calls.calls == [("get_server_pubkey", b"", None)]


def test_missing_attestation_is_null(client, enclave_calls):
    enclave_calls.responses["get_server_pubkey"]["data"]["attestation"] = None
    assert client.get("/get_server_pubkey", headers=AUTH).get_json()["attestation"] is None


# 0xfb 0xff encodes to "+/" in standard base64 and "-_" in base64url
NONCE = bytes([0xFB, 0xFF]) * 16


@pytest.mark.parametrize("encoded", [
    base64.urlsafe_b64encode(NONCE).decode().rstrip("="),   # base64url, unpadded (what chat.py may send)
    base64.urlsafe_b64encode(NONCE).decode(),
    base64.b64encode(NONCE).decode(),                        # standard base64
])
def test_nonce_encodings(client, enclave_calls, encoded):
    response = client.get("/get_server_pubkey", headers=AUTH, query_string={"nonce": encoded})
    assert response.status_code == 200
    assert enclave_calls.calls == [("get_server_pubkey", NONCE, None)]


def test_oversize_nonce_is_400(client, enclave_calls):
    response = client.get("/get_server_pubkey", headers=AUTH,
                          query_string={"nonce": base64.b64encode(b"n" * 65).decode()})
    assert response.status_code == 400
    assert "nonce" in response.get_json()["error"]
    assert enclave_calls.calls == []


def test_invalid_nonce_is_400(client, enclave_calls):
    assert client.get("/get_server_pubkey?nonce=@@@", headers=AUTH).status_code == 400


def test_enclave_error_is_502(client, enclave_calls):
    enclave_calls.responses["generate_text"] = {"status_code": 1, "error": "Unknown or expired session_id"}
    response = client.post("/generate_text", headers=AUTH,
                           json={"session_id": "sid-1", "encrypted_prompt": base64.b64encode(b"x").decode()})
    assert response.status_code == 502
    assert response.get_json() == {"error": "Unknown or expired session_id"}


def test_enclave_unreachable_is_502(client, enclave_calls, monkeypatch):
    def send_request(*args, **kwargs):
        raise ConnectionError("Could not connect to the enclave")

    monkeypatch.setattr(bridge, "send_request", send_request)
    response = client.get("/get_server_pubkey", headers=AUTH)
    assert response.status_code == 502
    assert "unreachable" in response.get_json()["error"]


@pytest.mark.parametrize("path,field", [
    ("/send_encrypted_client_seckey_a", "encrypted_seckey_a"),
    ("/send_client_pubkey_b", "encrypted_pubkey_b"),
    ("/generate_text", "encrypted_prompt"),
])
def test_bad_input_is_400(client, enclave_calls, path, field):
    good = base64.b64encode(b"ciphertext").decode()
    for body in (
        {"session_id": "sid-1", field: "!!not base64!!"},
        {"session_id": "sid-1"},
        {field: good},
        {"session_id": 7, field: good},
    ):
        assert client.post(path, headers=AUTH, json=body).status_code == 400, body
    assert client.post(path, headers=AUTH, data="not json", content_type="application/json").status_code == 400
    assert enclave_calls.calls == []


@pytest.mark.parametrize("path,field,method", [
    ("/send_encrypted_client_seckey_a", "encrypted_seckey_a", "send_encrypted_client_seckey_a"),
    ("/send_client_pubkey_b", "encrypted_pubkey_b", "send_client_pubkey_b"),
])
def test_key_relay(client, enclave_calls, path, field, method):
    response = client.post(path, headers=AUTH,
                           json={"session_id": "sid-1", field: base64.b64encode(b"wrapped").decode()})
    assert response.status_code == 200
    assert response.get_json() == {"status_code": 0}
    assert enclave_calls.calls == [(method, b"wrapped", "sid-1")]


def test_generate_text_returns_json(client, enclave_calls):
    response = client.post("/generate_text", headers=AUTH,
                           json={"session_id": "sid-1", "encrypted_prompt": base64.b64encode(b"prompt-ct").decode()})
    assert response.status_code == 200
    assert response.get_json() == {"encrypted_response": base64.b64encode(b"\x00\x01ciphertext").decode()}
    assert enclave_calls.calls == [("generate_text", b"prompt-ct", "sid-1")]
