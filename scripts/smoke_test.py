#!/usr/bin/env python3
"""End-to-end smoke test against chat.py: key exchange, then one encrypted prompt.

Drives the same sequence of calls the React UI makes (see control-plane/web/src/lib/api.ts).
Only the standard library is needed.

    python scripts/smoke_test.py                      # chat.py at http://localhost:8501/api
    CHAT_URL=http://host:8501/api python scripts/smoke_test.py --prompt "Hello"
"""
import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request

CHAT_URL = os.environ.get("CHAT_URL", "http://localhost:8501/api").rstrip("/")


def call(endpoint, payload=None, timeout=300):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        f"{CHAT_URL}/{endpoint}", data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def step(name, endpoint, payload=None):
    status, body = call(endpoint, payload)
    try:
        parsed = json.loads(body)
    except ValueError:
        parsed = {}
    ok = status == 200 and parsed.get("status", "success") == "success"
    print(f"[{'ok' if ok else 'FAIL'}] {name}: {parsed.get('message', '') or status}")
    if not ok:
        print(body.decode(errors="replace"))
        sys.exit(1)
    return parsed, body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prompt", default="In two sentences, what is a trusted execution environment?")
    args = ap.parse_args()

    # Key exchange, same order as the Key Management panel
    step("create key directory", "create_key_directory")
    step("get enclave public key", "retrieve_server_key")
    step("generate key A", "generate_key", {"key_name": "key_a"})
    step("generate key B", "generate_key", {"key_name": "key_b"})
    step("encrypt private key A with enclave key", "encrypt_key_a")
    step("send encrypted key A to enclave", "send_encrypted_key_a")
    step("send public key B to enclave", "send_public_key_b")

    # One chat turn
    enc, _ = step("encrypt prompt with key A", "encrypt_prompt", {"prompt": args.prompt})
    print("      ciphertext:", enc["encrypted_prompt"][:48] + "...")
    _, gen_body = step("generate text inside enclave", "generate_text",
                       {"encrypted_prompt": enc["encrypted_prompt"]})
    # api.ts base64-encodes the raw body of /generate_text and passes it to /decrypt_response
    dec, _ = step("decrypt response with key B", "decrypt_response",
                  {"encrypted_response": base64.b64encode(gen_body).decode()})
    print()
    print("prompt:  ", args.prompt)
    print("response:", dec["decrypted_response"])
    step("delete all keys", "delete_all_keys")


if __name__ == "__main__":
    main()
