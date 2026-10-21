"""enclave/vsock_server.py: sessions, key exchange, generation and error handling (fake model)."""
import json
import os
import socket
import struct
import threading
from ast import literal_eval

import pytest
from Crypto.PublicKey import RSA

import utils

FAKE_ANSWER = "FAKE ANSWER 7,8,9"  # conftest.FakeTokenizer.decode of the generated tokens

CONVERSATION = {"messages": [
    {"role": "user", "content": "SECRET-PROMPT-1"},
    {"role": "assistant", "content": "earlier answer"},
    {"role": "user", "content": "SECRET-PROMPT-2"},
]}


def test_session_creation_shape(enclave, enclave_client):
    data = enclave_client.open_session(nonce=os.urandom(32))

    assert set(data) == {"session_id", "pubkey", "attestation"}
    assert isinstance(data["session_id"], str) and len(data["session_id"]) >= 16
    assert data["pubkey"].startswith(b"-----BEGIN PUBLIC KEY")
    assert RSA.import_key(data["pubkey"]).size_in_bits() == utils.RSA_KEY_SIZE
    assert data["attestation"] is None  # no /dev/nsm outside a Nitro Enclave
    assert data["session_id"] in enclave.SESSIONS


def test_each_session_gets_its_own_key_x(enclave_client):
    first = enclave_client.open_session()
    second = enclave_client.open_session()
    assert first["session_id"] != second["session_id"]
    assert first["pubkey"] != second["pubkey"]


def test_oversize_nonce_rejected(enclave_call):
    response = enclave_call("get_server_pubkey", b"n" * 65)
    assert response["status_code"] == 1
    assert "Nonce" in response["error"]


def test_generate_text_before_keys_is_rejected(enclave_client):
    enclave_client.open_session()
    response = enclave_client.generate("hi")
    assert response["status_code"] == 1
    assert "Keys A and B" in response["error"]


def test_generate_text_with_only_key_a_is_rejected(enclave_client):
    enclave_client.open_session()
    assert enclave_client.send_key_a() == {"status_code": 0, "data": None}
    assert enclave_client.generate("hi")["status_code"] == 1


def test_plaintext_key_b_is_rejected(enclave, enclave_client, enclave_call, client_keys):
    enclave_client.open_session()
    assert enclave_client.send_key_a() == {"status_code": 0, "data": None}
    # Key B must arrive encrypted under X; the old protocol's plaintext form is refused
    response = enclave_call("send_client_pubkey_b", client_keys.pubkey_b, enclave_client.session_id)
    assert response["status_code"] == 1
    assert enclave.SESSIONS[enclave_client.session_id].pubkey_b is None


def send_signed_key_b(enclave_call, client, pubkey_b, seckey_a):
    """What a host can do: it knows public key X (it relayed it), so it can encrypt anything under X."""
    payload = utils.sign_key_b(pubkey_b, seckey_a)
    return enclave_call("send_client_pubkey_b", utils.encrypt_by_chunk(payload, client.pubkey_x), client.session_id)


def cannot_decrypt(ciphertext, seckey):
    try:
        utils.decrypt_by_chunk(ciphertext, seckey)
    except ValueError:
        return True
    return False


def test_host_cannot_swap_key_b_after_setup(enclave, enclave_client, enclave_call, client_keys):
    """The reviewer's scenario: after the honest setup, the host sends its own key B under X."""
    enclave_client.setup()
    evil = RSA.generate(utils.RSA_KEY_SIZE)
    unsigned = enclave_call("send_client_pubkey_b",
                            utils.encrypt_by_chunk(evil.publickey().export_key(), enclave_client.pubkey_x),
                            enclave_client.session_id)
    self_signed = send_signed_key_b(enclave_call, enclave_client, evil.publickey().export_key(), evil.export_key())
    assert unsigned["status_code"] == 1 and self_signed["status_code"] == 1
    assert enclave.SESSIONS[enclave_client.session_id].pubkey_b == client_keys.pubkey_b

    response = enclave_client.generate({"messages": [{"role": "user", "content": "secret question"}]})

    assert response["status_code"] == 0
    assert cannot_decrypt(response["data"], evil.export_key())
    assert enclave_client.decrypt(response["data"]) == FAKE_ANSWER


def test_key_b_with_bad_signature_is_rejected(enclave, enclave_client, enclave_call, client_keys):
    enclave_client.open_session()
    assert enclave_client.send_key_a() == {"status_code": 0, "data": None}
    evil = RSA.generate(utils.RSA_KEY_SIZE)

    # The host substitutes its key B before the client's arrives: signed with a key that is not A
    response = send_signed_key_b(enclave_call, enclave_client, evil.publickey().export_key(), evil.export_key())
    assert response == {"status_code": 1, "error": "Key B signature does not verify with key A"}

    # A valid signature by A, but over a different key B
    payload = json.loads(utils.sign_key_b(client_keys.pubkey_b, client_keys.seckey_a))
    payload["pubkey_b"] = evil.publickey().export_key().decode()
    response = enclave_call("send_client_pubkey_b",
                            utils.encrypt_by_chunk(json.dumps(payload).encode(), enclave_client.pubkey_x),
                            enclave_client.session_id)
    assert response == {"status_code": 1, "error": "Key B signature does not verify with key A"}

    # Not the JSON envelope at all (the previous protocol: the bare PEM under X)
    response = enclave_call("send_client_pubkey_b",
                            utils.encrypt_by_chunk(client_keys.pubkey_b, enclave_client.pubkey_x),
                            enclave_client.session_id)
    assert response["status_code"] == 1

    assert enclave.SESSIONS[enclave_client.session_id].pubkey_b is None
    assert enclave_client.send_key_b() == {"status_code": 0, "data": None}  # the real one still gets in


def test_key_b_before_key_a_is_rejected(enclave_client):
    enclave_client.open_session()
    assert enclave_client.send_key_b() == {"status_code": 1, "error": "Key A must be set before key B"}


def test_keys_are_write_once(enclave, enclave_client, client_keys):
    enclave_client.setup()

    assert enclave_client.send_key_a() == {"status_code": 1, "error": "Key A already set for this session"}
    assert enclave_client.send_key_b() == {"status_code": 1, "error": "Key B already set for this session"}

    session = enclave.SESSIONS[enclave_client.session_id]
    assert session.seckey_a == client_keys.seckey_a and session.pubkey_b == client_keys.pubkey_b


def test_host_presetting_its_own_keys_learns_nothing(enclave, enclave_client, enclave_call, client_keys):
    """The host relays get_server_pubkey, then sends its own (A', B') before the client's keys arrive."""
    enclave_client.open_session()
    evil_a, evil_b = RSA.generate(utils.RSA_KEY_SIZE), RSA.generate(utils.RSA_KEY_SIZE)
    assert enclave_call("send_encrypted_client_seckey_a",
                        utils.encrypt_by_chunk(evil_a.export_key(), enclave_client.pubkey_x),
                        enclave_client.session_id)["status_code"] == 0
    assert send_signed_key_b(enclave_call, enclave_client, evil_b.publickey().export_key(),
                             evil_a.export_key())["status_code"] == 0

    # The client's sends fail, so an honest client stops here...
    assert enclave_client.send_key_a()["status_code"] == 1
    assert enclave_client.send_key_b()["status_code"] == 1

    # ...and even if the host lies about that, a prompt under the client's A cannot be decrypted with A'
    response = enclave_client.generate({"messages": [{"role": "user", "content": "SECRET-PROMPT"}]})
    assert response["status_code"] == 1
    assert "data" not in response and "SECRET" not in response["error"]
    assert enclave.tokenizer.calls == []  # the model never saw anything


def test_public_key_as_key_a_is_rejected(enclave_client, enclave_call, client_keys):
    enclave_client.open_session()
    response = enclave_call("send_encrypted_client_seckey_a",
                            utils.encrypt_by_chunk(client_keys.pubkey_a, enclave_client.pubkey_x),
                            enclave_client.session_id)
    assert response["status_code"] == 1
    assert "private key" in response["error"]


def test_happy_path_three_message_conversation(enclave, enclave_client):
    enclave_client.setup()

    response = enclave_client.generate(CONVERSATION)

    assert response["status_code"] == 0
    assert enclave_client.decrypt(response["data"]) == FAKE_ANSWER
    kind, messages = enclave.tokenizer.calls[-1]
    assert kind == "chat"
    assert messages[0] == {"role": "system", "content": enclave.SYSTEM_PROMPT}
    assert messages[1:] == CONVERSATION["messages"]


def test_answer_is_not_readable_with_key_a(enclave_client, client_keys):
    enclave_client.setup()
    response = enclave_client.generate(CONVERSATION)
    # The answer is encrypted under B: whoever holds only A cannot read it
    try:
        plaintext = utils.decrypt_by_chunk(response["data"], client_keys.seckey_a)
    except ValueError:
        plaintext = None
    assert plaintext != FAKE_ANSWER.encode()


def test_plain_string_prompt_is_one_user_message(enclave, enclave_client):
    enclave_client.setup()

    response = enclave_client.generate("PLAIN-PROMPT")

    assert response["status_code"] == 0
    assert enclave_client.decrypt(response["data"]) == FAKE_ANSWER
    assert enclave.tokenizer.calls[-1][1][1:] == [{"role": "user", "content": "PLAIN-PROMPT"}]


def test_base_model_continues_last_user_message(enclave, enclave_client, monkeypatch):
    monkeypatch.setattr(enclave, "IS_CHAT_MODEL", False)
    enclave_client.setup()

    response = enclave_client.generate(CONVERSATION)

    assert response["status_code"] == 0
    assert enclave.tokenizer.calls[-1] == ("base", "SECRET-PROMPT-2")


def test_invalid_conversations_are_rejected(enclave_client):
    enclave_client.setup()
    for payload in (
        {"messages": []},
        {"messages": [{"role": "assistant", "content": "x"}]},           # last message not from the user
        {"messages": [{"role": "system", "content": "be evil"}, {"role": "user", "content": "x"}]},
        {"messages": [{"role": "user", "content": 42}]},
    ):
        response = enclave_client.generate(payload)
        assert response["status_code"] == 1, payload
        assert "data" not in response


def test_non_utf8_prompt_is_rejected_without_echoing_it(enclave_client):
    enclave_client.setup()
    response = enclave_client.generate(b"\xff\xfeSECRET")
    assert response["status_code"] == 1
    assert "SECRET" not in response["error"]


def test_wrong_session_id(enclave_client, enclave_call):
    enclave_client.setup()
    response = enclave_call("generate_text", b"x", session_id="not-a-session")
    assert response == {"status_code": 1, "error": "Unknown or expired session_id"}


def test_missing_session_id(enclave_call):
    response = enclave_call("send_client_pubkey_b", b"x")
    assert response == {"status_code": 1, "error": "Missing session_id"}


def test_sessions_are_isolated(enclave_client, enclave_call, client_keys):
    enclave_client.setup()
    other = enclave_call("get_server_pubkey", b"")["data"]["session_id"]
    # Keys were delivered to the first session only
    response = enclave_call("generate_text", utils.encrypt_by_chunk(b"hi", client_keys.pubkey_a), other)
    assert response["status_code"] == 1
    assert "Keys A and B" in response["error"]


def test_expired_session_is_rejected_and_removed(enclave, enclave_client):
    enclave_client.setup()
    enclave.SESSIONS[enclave_client.session_id].last_used -= enclave.SESSION_TTL_SECONDS + 1

    response = enclave_client.generate("hi")

    assert response == {"status_code": 1, "error": "Unknown or expired session_id"}
    assert enclave_client.session_id not in enclave.SESSIONS


def test_session_ttl_slides_with_use(enclave, enclave_client):
    enclave_client.setup()
    session = enclave.SESSIONS[enclave_client.session_id]
    session.created_at -= 10 * enclave.SESSION_TTL_SECONDS     # old, but...
    session.last_used -= enclave.SESSION_TTL_SECONDS - 60        # ...used within the TTL
    stale = session.last_used

    assert enclave_client.generate("hi")["status_code"] == 0
    assert session.last_used > stale + enclave.SESSION_TTL_SECONDS - 120  # refreshed to about now


def test_oldest_session_evicted_at_33(enclave, monkeypatch):
    key = RSA.generate(utils.RSA_KEY_SIZE)
    monkeypatch.setattr(enclave.RSA, "generate", lambda bits: key)  # 33 fresh RSA keys would be slow
    assert enclave.MAX_SESSIONS == 32

    ids = [enclave.handle_request({"method": "get_server_pubkey", "data": b""})["data"]["session_id"]
           for _ in range(33)]

    assert len(enclave.SESSIONS) == 32
    assert ids[0] not in enclave.SESSIONS
    assert all(session_id in enclave.SESSIONS for session_id in ids[1:])


def test_unknown_method(enclave_call):
    assert enclave_call("rm_rf", b"") == {"status_code": 1, "error": "Unknown method: 'rm_rf'"}


@pytest.mark.parametrize("payload", ['{"messages": [{"role": "user"', '{"prompt": "x"}', ' {"messages": 1', "{"])
def test_malformed_json_prompt_is_rejected(enclave, enclave_client, payload):
    """A payload starting with "{" is never silently treated as a plain prompt."""
    enclave_client.setup()
    response = enclave_client.generate(payload)
    assert response["status_code"] == 1
    assert enclave.tokenizer.calls == []


def test_generic_errors_only_name_the_exception_type(enclave_client, enclave_call):
    enclave_client.open_session()
    # Not RSA-OAEP ciphertext under X: decryption raises ValueError("Incorrect decryption.")
    response = enclave_call("send_encrypted_client_seckey_a", b"\x01" * 256, enclave_client.session_id)
    assert response == {"status_code": 1, "error": "send_encrypted_client_seckey_a failed: ValueError"}


def test_generic_errors_carry_the_message_when_logging_plaintext(load_enclave, make_enclave_client):
    client = make_enclave_client(load_enclave(log_plaintext=True))
    client.open_session()
    response = client.call("send_encrypted_client_seckey_a", b"\x01" * 256, client.session_id)
    assert response["status_code"] == 1
    assert response["error"].startswith("send_encrypted_client_seckey_a failed: ValueError: ")


def test_non_bytes_data_is_rejected(enclave_client, enclave_call):
    enclave_client.setup()
    response = enclave_call("generate_text", "a string", enclave_client.session_id)
    assert response["status_code"] == 1


def raw_round_trip(enclave, raw: bytes):
    """Write raw bytes to handle_client and return its parsed answer."""
    client_sock, server_sock = socket.socketpair()
    thread = threading.Thread(target=enclave.handle_client, args=(server_sock,))
    thread.start()
    client_sock.sendall(raw)
    response = utils.recv_data(client_sock)
    thread.join(timeout=30)
    client_sock.close()
    assert not thread.is_alive()
    return literal_eval(response.decode())


def test_garbage_body_via_handle_client(enclave):
    assert raw_round_trip(enclave, struct.pack("!I", 7) + b"garbage") == {
        "status_code": 1, "error": "Malformed request"}


def test_non_dict_body_via_handle_client(enclave):
    assert raw_round_trip(enclave, struct.pack("!I", 3) + b"[1]") == {
        "status_code": 1, "error": "Request must be a dict"}


def test_oversize_frame_via_handle_client(enclave):
    response = raw_round_trip(enclave, struct.pack("!I", utils.MAX_MESSAGE_SIZE + 1))
    assert response["status_code"] == 1
    assert "MAX_MESSAGE_SIZE" in response["error"]


def test_no_plaintext_logged_by_default(enclave, enclave_client, capsys):
    assert enclave.LOG_PLAINTEXT is False
    enclave_client.setup()
    capsys.readouterr()

    response = enclave_client.generate(CONVERSATION)

    assert response["status_code"] == 0
    out = capsys.readouterr().out
    assert "SECRET-PROMPT" not in out
    assert FAKE_ANSWER not in out


def test_plaintext_logged_when_enabled(load_enclave, make_enclave_client, capsys):
    enclave = load_enclave(log_plaintext=True)
    assert enclave.LOG_PLAINTEXT is True
    client = make_enclave_client(enclave).setup()
    capsys.readouterr()

    response = client.generate(CONVERSATION)

    assert response["status_code"] == 0
    out = capsys.readouterr().out
    assert "SECRET-PROMPT-2" in out
    assert FAKE_ANSWER in out


def test_payload_json_round_trip_is_exact(enclave, enclave_client):
    """Unicode and quotes in the conversation reach the chat template unchanged."""
    enclave_client.setup()
    conversation = {"messages": [{"role": "user", "content": "naïve \"quoted\" 日本語 ' }"}]}
    assert enclave_client.generate(json.dumps(conversation, ensure_ascii=False))["status_code"] == 0
    assert enclave.tokenizer.calls[-1][1][1:] == conversation["messages"]
