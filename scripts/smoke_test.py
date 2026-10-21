#!/usr/bin/env python3
"""End-to-end smoke test against chat.py: key exchange, then one encrypted prompt.

Drives the same sequence of calls the React UI makes (see control-plane/web/src/lib/api.ts).
Only the standard library is needed.

    python scripts/smoke_test.py                      # chat.py at http://localhost:8501/api
    CHAT_URL=http://host:8501/api python scripts/smoke_test.py --prompt "Hello"
    API_TOKEN=... python scripts/smoke_test.py          # when chat.py requires a bearer token
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

CHAT_URL = os.environ.get("CHAT_URL", "http://localhost:8501/api").rstrip("/")
API_TOKEN = os.environ.get("API_TOKEN", "")


def call(endpoint, payload=None, timeout=300):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    req = urllib.request.Request(f"{CHAT_URL}/{endpoint}", data=data, headers=headers)
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
        print(f"      HTTP {status}")
        print(body.decode(errors="replace"))
        sys.exit(1)
    return parsed, body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prompt", default="In two sentences, what is a trusted execution environment?")
    args = ap.parse_args()

    # Key exchange, same order as the Key Management panel
    step("create key directory", "create_key_directory")
    key, _ = step("get enclave public key", "retrieve_server_key")
    att = key.get("attestation") or {}
    print(f"      attestation: mode={att.get('mode')} verified={att.get('verified')} "
          f"chain_valid={att.get('chain_valid')} pcr0={att.get('pcr0')}")
    for error in att.get("errors") or []:
        print(f"      attestation error: {error}")
    step("generate key A", "generate_key", {"key_name": "key_a"})
    step("generate key B", "generate_key", {"key_name": "key_b"})
    step("encrypt private key A with enclave key", "encrypt_key_a")
    step("send encrypted key A to enclave", "send_encrypted_key_a")
    step("send public key B to enclave", "send_public_key_b")

    # One chat turn (the full conversation so far; here a single user message)
    messages = [{"role": "user", "content": args.prompt}]
    enc, _ = step("encrypt prompt with key A", "encrypt_prompt", {"messages": messages})
    print("      ciphertext:", enc["encrypted_prompt"][:48] + "...")
    gen, _ = step("generate text inside enclave", "generate_text",
                  {"encrypted_prompt": enc["encrypted_prompt"]})
    dec, _ = step("decrypt response with key B", "decrypt_response",
                  {"encrypted_response": gen["encrypted_response"]})
    print()
    print("prompt:  ", args.prompt)
    print("response:", dec["decrypted_response"])
    step("delete all keys", "delete_all_keys")


if __name__ == "__main__":
    main()
