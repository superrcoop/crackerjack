"""Tests for zero-knowledge ephemeral secret vault, client-side encryption, and REST handlers."""

from io import BytesIO
import json
import time
from http import HTTPStatus
from typing import Any

from crackerjack.vault import (
    VaultStore,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    decrypt_secret,
    encrypt_secret,
    parse_vault_url,
)
from crackerjack.server import CrackerjackRequestHandler, GLOBAL_VAULT


class VaultInMemoryHandler(CrackerjackRequestHandler):
    """In-memory test harness capturing responses without opening TCP sockets."""
    def __init__(self, path: str = ""):
        self.path = path
        self.headers = {}
        self.client_address = ("127.0.0.1", 54321)
        self.last_status = None
        self.last_data = None
        self.response_headers = {}
        self.wfile = BytesIO()

    def send_response(self, status: int) -> None:
        self.last_status = status

    def send_header(self, key: str, value: str) -> None:
        self.response_headers[key] = value

    def end_headers(self) -> None:
        pass

    def _send_cors_headers(self) -> None:
        pass

    def _send_json_response(self, status: int, data: Any) -> None:
        self.last_status = status
        self.last_data = data


def test_aes_gcm_encrypt_decrypt_roundtrip():
    key = b"01234567890123456789012345678901"  # 32 bytes
    iv = b"123456789012"  # 12 bytes
    plaintext = b"super-secret-credentials-2026"

    ciphertext, tag = aes_gcm_encrypt(key, iv, plaintext)
    assert len(ciphertext) == len(plaintext)
    assert len(tag) == 16
    assert ciphertext != plaintext

    decrypted = aes_gcm_decrypt(key, iv, ciphertext, tag)
    assert decrypted == plaintext


def test_aes_gcm_tampered_fails():
    key = b"01234567890123456789012345678901"
    iv = b"123456789012"
    plaintext = b"sensitive-data"

    ciphertext, tag = aes_gcm_encrypt(key, iv, plaintext)

    # Tamper with ciphertext
    tampered_cipher = bytearray(ciphertext)
    tampered_cipher[0] ^= 0xFF
    failed = False
    try:
        aes_gcm_decrypt(key, iv, bytes(tampered_cipher), tag)
    except Exception:
        failed = True
    assert failed, "Tampered ciphertext should have raised an exception"

    # Tamper with tag
    tampered_tag = bytearray(tag)
    tampered_tag[0] ^= 0xFF
    failed = False
    try:
        aes_gcm_decrypt(key, iv, ciphertext, bytes(tampered_tag))
    except Exception:
        failed = True
    assert failed, "Tampered tag should have raised an exception"

    # Wrong key
    wrong_key = b"wrong-key-0000000000000000000000"
    failed = False
    try:
        aes_gcm_decrypt(wrong_key, iv, ciphertext, tag)
    except Exception:
        failed = True
    assert failed, "Wrong key should have raised an exception"


def test_encrypt_decrypt_secret_high_level():
    secret_text = "DATABASE_URL=postgres://user:p@ss@prod.internal:5432/core\nAWS_SECRET=xyz123"
    payload, key_b64 = encrypt_secret(secret_text, ttl_seconds=3600, burn_on_read=True, allow_ip="10.0.0.1")

    assert payload["id"].startswith("vlt_")
    assert payload["burn_on_read"] is True
    assert payload["allow_ip"] == "10.0.0.1"
    assert payload["expires_at"] > time.time()
    assert isinstance(payload["ciphertext"], str)

    # Recover plaintext
    decrypted = decrypt_secret(payload["ciphertext"], key_b64)
    assert decrypted == secret_text


def test_parse_vault_url():
    url1 = "https://crackerjack-security.pages.dev/#vault?id=vlt_12345678&key=abcdefghijk"
    sid1, k1 = parse_vault_url(url1)
    assert sid1 == "vlt_12345678"
    assert k1 == "abcdefghijk"

    url2 = "https://example.com/vault#id=vlt_abcd&key=secretkey"
    sid2, k2 = parse_vault_url(url2)
    assert sid2 == "vlt_abcd"
    assert k2 == "secretkey"

    failed = False
    try:
        parse_vault_url("https://example.com/no-hash-params")
    except ValueError:
        failed = True
    assert failed, "URL missing hash parameters should fail"


def test_vault_store_burn_on_read():
    store = VaultStore()
    payload = {
        "id": "vlt_burn_test",
        "ciphertext": "dummy_ciphertext",
        "burn_on_read": True,
        "expires_at": int(time.time()) + 300,
    }
    store.put(payload)
    assert store.count() == 1

    # First fetch succeeds and burns
    rec = store.get("vlt_burn_test")
    assert rec is not None
    assert rec["ciphertext"] == "dummy_ciphertext"

    # Second fetch returns None (already burned)
    assert store.get("vlt_burn_test") is None
    assert store.count() == 0


def test_vault_store_no_burn():
    store = VaultStore()
    payload = {
        "id": "vlt_persist_test",
        "ciphertext": "dummy_persist",
        "burn_on_read": False,
        "expires_at": int(time.time()) + 300,
    }
    store.put(payload)

    # Multiple gets succeed
    assert store.get("vlt_persist_test") is not None
    assert store.get("vlt_persist_test") is not None
    assert store.count() == 1


def test_vault_store_expiration():
    store = VaultStore()
    payload = {
        "id": "vlt_expired_test",
        "ciphertext": "dummy_expired",
        "burn_on_read": True,
        "expires_at": int(time.time()) - 10,  # Already expired
    }
    store.put(payload)

    assert store.get("vlt_expired_test") is None
    assert store.count() == 0


def test_vault_store_ip_allowlist():
    store = VaultStore()
    payload = {
        "id": "vlt_ip_test",
        "ciphertext": "dummy_ip_data",
        "burn_on_read": False,
        "expires_at": int(time.time()) + 300,
        "allow_ip": "192.168.1.100",
    }
    store.put(payload)

    # Denied from foreign IP
    failed = False
    try:
        store.get("vlt_ip_test", client_ip="10.0.0.5")
    except PermissionError:
        failed = True
    assert failed, "Foreign IP should raise PermissionError"

    # Allowed from matching IP
    rec = store.get("vlt_ip_test", client_ip="192.168.1.100")
    assert rec is not None


def test_server_vault_endpoints():
    handler = VaultInMemoryHandler()

    # Create secret via API
    secret_payload, key_b64 = encrypt_secret("my-super-secret-db-key", ttl_seconds=600, burn_on_read=True)
    handler._handle_vault(secret_payload)

    assert handler.last_status == HTTPStatus.CREATED
    assert handler.last_data["id"] == secret_payload["id"]

    # Retrieve secret via GET handler
    get_handler = VaultInMemoryHandler(path=f"/v1/vault/{secret_payload['id']}")
    get_handler.do_GET()

    assert get_handler.last_status == HTTPStatus.OK
    ciphertext_returned = get_handler.last_data["ciphertext"]

    # Decrypt client-side
    recovered = decrypt_secret(ciphertext_returned, key_b64)
    assert recovered == "my-super-secret-db-key"

    # Second GET must return 404 (Burn on read)
    second_get = VaultInMemoryHandler(path=f"/v1/vault/{secret_payload['id']}")
    second_get.do_GET()
    assert second_get.last_status == HTTPStatus.NOT_FOUND


if __name__ == "__main__":
    test_aes_gcm_encrypt_decrypt_roundtrip()
    test_aes_gcm_tampered_fails()
    test_encrypt_decrypt_secret_high_level()
    test_parse_vault_url()
    test_vault_store_burn_on_read()
    test_vault_store_no_burn()
    test_vault_store_expiration()
    test_vault_store_ip_allowlist()
    test_server_vault_endpoints()
    print("ALL 9 VAULT TESTS PASSED CLEANLY AND INSTANTLY!")
