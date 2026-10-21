"""Shared fixtures: the enclave server (enclave/vsock_server.py) with a fake model, and the client
side of the enclave protocol (nonce -> session, key A and key B (signed with A) encrypted under X,
prompts under A).

`transformers` is replaced by a stub before vsock_server is imported, so neither torch nor
transformers nor model weights are needed. pytest.ini puts common/, enclave/, data-plane/ and
control-plane/api/ on sys.path.
"""
import importlib
import json
import socket
import sys
import threading
import types
from ast import literal_eval

import pytest
from Crypto.PublicKey import RSA

import utils


class FakeIds(list):
    @property
    def shape(self):
        return (1, len(self[0]))


class FakeTokenizer:
    """Chat-model tokenizer: has a chat_template and records what it was asked to format."""

    chat_template = "{{ fake }}"
    pad_token_id = 0
    eos_token = "<eos>"

    def __init__(self):
        self.calls = []  # ("chat", messages) or ("base", prompt)

    def apply_chat_template(self, messages, tokenize, add_generation_prompt):
        self.calls.append(("chat", messages))
        return "CHAT:" + json.dumps(messages)

    def __call__(self, text, return_tensors):
        return {"input_ids": FakeIds([[1, 2, 3]])}

    def encode(self, text, return_tensors):
        self.calls.append(("base", text))
        return [[1, 2, 3]]

    def decode(self, tokens, skip_special_tokens):
        return "FAKE ANSWER " + ",".join(str(t) for t in tokens)


class FakeModel:
    def generate(self, *args, **kwargs):
        return [[1, 2, 3, 7, 8, 9]]  # the 3 prompt tokens + 3 "generated" ones


def make_fake_transformers():
    module = types.ModuleType("transformers")
    module.AutoTokenizer = types.SimpleNamespace(from_pretrained=lambda *a, **k: FakeTokenizer())
    module.AutoModelForCausalLM = types.SimpleNamespace(from_pretrained=lambda *a, **k: FakeModel())
    return module


@pytest.fixture
def load_enclave(monkeypatch):
    """Factory: import enclave/vsock_server.py fresh (empty SESSIONS) with the fake model."""

    def load(log_plaintext=False):
        monkeypatch.setenv("ENCLAVE_TRANSPORT", "tcp")
        if log_plaintext:
            monkeypatch.setenv("ENCLAVE_LOG_PLAINTEXT", "true")
        else:
            monkeypatch.delenv("ENCLAVE_LOG_PLAINTEXT", raising=False)
        monkeypatch.setitem(sys.modules, "transformers", make_fake_transformers())
        sys.modules.pop("vsock_server", None)
        return importlib.import_module("vsock_server")

    yield load
    sys.modules.pop("vsock_server", None)


@pytest.fixture
def enclave(load_enclave):
    return load_enclave()


def wire_call(server, request: dict) -> dict:
    """Send one framed request to server.handle_client over a socketpair, like vsock_client does."""
    client_sock, server_sock = socket.socketpair()
    thread = threading.Thread(target=server.handle_client, args=(server_sock,))
    thread.start()
    try:
        utils.send_data(client_sock, str(request).encode())
        response = utils.recv_data(client_sock)
    finally:
        thread.join(timeout=30)
        client_sock.close()
    assert response is not None, "enclave closed the connection without a response"
    return literal_eval(response.decode())


def call_for(server):
    """callable(method, data=b"", session_id=None) -> response dict, over the wire format."""

    def call(method, data=b"", session_id=None):
        request = {"method": method, "data": data}
        if session_id is not None:
            request["session_id"] = session_id
        return wire_call(server, request)

    return call


@pytest.fixture
def enclave_call(enclave):
    return call_for(enclave)


@pytest.fixture(scope="session")
def client_keys():
    """Client key pairs A (prompts) and B (answers), generated once per test run."""
    key_a, key_b = RSA.generate(utils.RSA_KEY_SIZE), RSA.generate(utils.RSA_KEY_SIZE)
    return types.SimpleNamespace(
        seckey_a=key_a.export_key(), pubkey_a=key_a.publickey().export_key(),
        seckey_b=key_b.export_key(), pubkey_b=key_b.publickey().export_key(),
    )


class EnclaveClient:
    """The client half of the protocol (what chat.py + the data plane do), step by step."""

    def __init__(self, call, keys):
        self.call = call
        self.keys = keys
        self.session_id = None
        self.pubkey_x = None

    def open_session(self, nonce=b""):
        response = self.call("get_server_pubkey", nonce)
        assert response["status_code"] == 0, response
        self.session_id = response["data"]["session_id"]
        self.pubkey_x = response["data"]["pubkey"]
        return response["data"]

    def send_key_a(self):
        return self.call("send_encrypted_client_seckey_a",
                         utils.encrypt_by_chunk(self.keys.seckey_a, self.pubkey_x), self.session_id)

    def send_key_b(self):
        payload = utils.sign_key_b(self.keys.pubkey_b, self.keys.seckey_a)
        return self.call("send_client_pubkey_b", utils.encrypt_by_chunk(payload, self.pubkey_x), self.session_id)

    def setup(self, nonce=b""):
        """Session + both keys, ready for generate_text."""
        self.open_session(nonce)
        assert self.send_key_a() == {"status_code": 0, "data": None}
        assert self.send_key_b() == {"status_code": 0, "data": None}
        return self

    def generate(self, payload):
        """payload: dict (sent as JSON), str or bytes; encrypted under key A."""
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        if isinstance(payload, str):
            payload = payload.encode()
        return self.call("generate_text", utils.encrypt_by_chunk(payload, self.keys.pubkey_a), self.session_id)

    def decrypt(self, ciphertext: bytes) -> str:
        return utils.decrypt_by_chunk(ciphertext, self.keys.seckey_b).decode()


@pytest.fixture
def make_enclave_client(client_keys):
    """Factory: an EnclaveClient talking to a given vsock_server module."""
    return lambda server: EnclaveClient(call_for(server), client_keys)


@pytest.fixture
def enclave_client(enclave, make_enclave_client):
    return make_enclave_client(enclave)
