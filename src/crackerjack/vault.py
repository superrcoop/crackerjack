"""Zero-knowledge ephemeral secret vault with client-side AES-256-GCM encryption."""

from __future__ import annotations

import base64
import ctypes
import ctypes.util
import os
import secrets
import sys
import threading
import time
from typing import Any, Optional


# ---------------------------------------------------------------------------
# AES-256-GCM Cryptographic Primitives (System OpenSSL via ctypes + cryptography fallback)
# ---------------------------------------------------------------------------

_CRYPTO_LIB = None

def _load_crypto_lib():
    global _CRYPTO_LIB
    if _CRYPTO_LIB is not None:
        return _CRYPTO_LIB

    # Try standard library paths
    lib_path = ctypes.util.find_library("crypto")
    candidates = [
        lib_path,
        "/usr/lib/libcrypto.dylib",
        "/opt/homebrew/lib/libcrypto.dylib",
        "/usr/local/lib/libcrypto.dylib",
        "libcrypto.so",
        "libcrypto.so.3",
        "libcrypto.so.1.1",
    ]

    for cand in candidates:
        if cand:
            try:
                _CRYPTO_LIB = ctypes.CDLL(cand)
                break
            except Exception:
                continue

    if _CRYPTO_LIB is not None:
        try:
            _CRYPTO_LIB.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
            _CRYPTO_LIB.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
            _CRYPTO_LIB.EVP_aes_256_gcm.restype = ctypes.c_void_p

            _CRYPTO_LIB.EVP_EncryptInit_ex.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p
            ]
            _CRYPTO_LIB.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
            _CRYPTO_LIB.EVP_EncryptUpdate.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int
            ]
            _CRYPTO_LIB.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]

            _CRYPTO_LIB.EVP_DecryptInit_ex.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p
            ]
            _CRYPTO_LIB.EVP_DecryptUpdate.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int
            ]
            _CRYPTO_LIB.EVP_DecryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
        except Exception:
            _CRYPTO_LIB = None

    return _CRYPTO_LIB


def _b64encode_urlsafe(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode_urlsafe(s: str) -> bytes:
    padding = (4 - len(s) % 4) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM. Returns (ciphertext, 16-byte authentication tag)."""
    # Try cryptography package first if installed
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        out = aesgcm.encrypt(iv, plaintext, None)
        return out[:-16], out[-16:]
    except ImportError:
        pass

    # Use system OpenSSL via ctypes
    crypto = _load_crypto_lib()
    if crypto is None:
        raise RuntimeError("OpenSSL libcrypto not found. Install 'cryptography' or ensure OpenSSL is on PATH.")

    EVP_CTRL_GCM_SET_IVLEN = 0x9
    EVP_CTRL_GCM_GET_TAG = 0x10

    ctx = crypto.EVP_CIPHER_CTX_new()
    try:
        crypto.EVP_EncryptInit_ex(ctx, crypto.EVP_aes_256_gcm(), None, None, None)
        crypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(iv), None)
        crypto.EVP_EncryptInit_ex(ctx, None, None, key, iv)

        out = (ctypes.c_char * (len(plaintext) + 16))()
        out_len = ctypes.c_int(0)
        crypto.EVP_EncryptUpdate(ctx, out, ctypes.byref(out_len), plaintext, len(plaintext))

        final_len = ctypes.c_int(0)
        crypto.EVP_EncryptFinal_ex(ctx, ctypes.byref(out, out_len.value), ctypes.byref(final_len))

        tag = (ctypes.c_char * 16)()
        crypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)

        ciphertext = bytes(out[: out_len.value + final_len.value])
        return ciphertext, bytes(tag)
    finally:
        crypto.EVP_CIPHER_CTX_free(ctx)


def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Decrypt and verify ciphertext using AES-256-GCM. Raises ValueError on authentication failure."""
    # Try cryptography package first if installed
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, ciphertext + tag, None)
    except ImportError:
        pass

    # Use system OpenSSL via ctypes
    crypto = _load_crypto_lib()
    if crypto is None:
        raise RuntimeError("OpenSSL libcrypto not found. Install 'cryptography' or ensure OpenSSL is on PATH.")

    EVP_CTRL_GCM_SET_IVLEN = 0x9
    EVP_CTRL_GCM_SET_TAG = 0x11

    d_ctx = crypto.EVP_CIPHER_CTX_new()
    try:
        crypto.EVP_DecryptInit_ex(d_ctx, crypto.EVP_aes_256_gcm(), None, None, None)
        crypto.EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_IVLEN, len(iv), None)
        crypto.EVP_DecryptInit_ex(d_ctx, None, None, key, iv)

        d_out = (ctypes.c_char * (len(ciphertext) + 16))()
        d_out_len = ctypes.c_int(0)
        crypto.EVP_DecryptUpdate(d_ctx, d_out, ctypes.byref(d_out_len), ciphertext, len(ciphertext))

        tag_buf = (ctypes.c_char * 16).from_buffer_copy(tag)
        crypto.EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_TAG, 16, tag_buf)

        final_len = ctypes.c_int(0)
        ret = crypto.EVP_DecryptFinal_ex(d_ctx, ctypes.byref(d_out, d_out_len.value), ctypes.byref(final_len))

        if ret != 1:
            raise ValueError("Decryption failed: corrupted data or invalid decryption key.")

        return bytes(d_out[: d_out_len.value + final_len.value])
    finally:
        crypto.EVP_CIPHER_CTX_free(d_ctx)


# ---------------------------------------------------------------------------
# High-Level Vault Encryption / Decryption
# ---------------------------------------------------------------------------

def encrypt_secret(
    plaintext: str,
    ttl_seconds: int = 3600,
    burn_on_read: bool = True,
    allow_ip: Optional[str] = None,
) -> tuple[dict[str, Any], str]:
    """
    Encrypt a plaintext secret client-side using AES-256-GCM.

    Returns:
        (payload_dict, url_safe_b64_key)
        - payload_dict: { id, ciphertext, burn_on_read, expires_at, allow_ip }
        - url_safe_b64_key: 32-byte key formatted for the URL fragment (#key=...)
    """
    key = secrets.token_bytes(32)
    iv = secrets.token_bytes(12)

    ciphertext, tag = aes_gcm_encrypt(key, iv, plaintext.encode("utf-8"))

    # Combined payload: iv (12 bytes) + ciphertext + tag (16 bytes)
    combined = iv + ciphertext + tag
    combined_b64 = _b64encode_urlsafe(combined)
    key_b64 = _b64encode_urlsafe(key)

    secret_id = f"vlt_{secrets.token_hex(8)}"
    now = int(time.time())
    expires_at = now + max(60, ttl_seconds)

    payload = {
        "id": secret_id,
        "ciphertext": combined_b64,
        "burn_on_read": bool(burn_on_read),
        "expires_at": expires_at,
        "allow_ip": allow_ip.strip() if allow_ip else None,
        "created_at": now,
    }

    return payload, key_b64


def decrypt_secret(ciphertext_b64: str, key_b64: str) -> str:
    """
    Decrypt combined base64 ciphertext using the URL fragment key.
    """
    try:
        key = _b64decode_urlsafe(key_b64)
        combined = _b64decode_urlsafe(ciphertext_b64)
    except Exception as e:
        raise ValueError(f"Malformed base64 ciphertext or key: {str(e)}") from e

    if len(key) != 32:
        raise ValueError("Invalid key length: AES-256 requires exactly 32 bytes.")

    if len(combined) < 28:  # 12 (iv) + 16 (tag)
        raise ValueError("Ciphertext blob is too short to contain valid IV and tag.")

    iv = combined[:12]
    tag = combined[-16:]
    ciphertext = combined[12:-16]

    plaintext_bytes = aes_gcm_decrypt(key, iv, ciphertext, tag)
    return plaintext_bytes.decode("utf-8")


def parse_vault_url(url: str) -> tuple[str, str]:
    """
    Extract secret (id, key) from a Crackerjack Vault URL fragment or query.
    Example: https://crackerjack-security.pages.dev/#vault?id=vlt_123&key=abc
             or https://domain/vault#id=vlt_123&key=abc
    """
    hash_part = ""
    if "#" in url:
        hash_part = url.split("#", 1)[1]
    elif "?" in url:
        hash_part = url.split("?", 1)[1]
    else:
        raise ValueError("Invalid Vault URL: Missing '#id=...&key=...' hash parameters.")

    # Remove optional leading 'vault?' if present (e.g. '#vault?id=...')
    if "?" in hash_part:
        hash_part = hash_part.split("?", 1)[1]

    params: dict[str, str] = {}
    for pair in hash_part.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            params[k.strip()] = v.strip()

    secret_id = params.get("id")
    key = params.get("key")

    if not secret_id or not key:
        raise ValueError("Vault URL must contain both 'id' and 'key' parameters.")

    return secret_id, key


# ---------------------------------------------------------------------------
# Thread-Safe In-Memory & Ephemeral Vault Storage
# ---------------------------------------------------------------------------

class VaultStore:
    """In-memory thread-safe ephemeral secret store with automatic expiration and burn-on-read."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._store: dict[str, dict[str, Any]] = {}

    def put(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Store an encrypted secret record."""
        secret_id = payload["id"]
        with self._lock:
            self._purge_expired_locked()
            self._store[secret_id] = {
                "id": secret_id,
                "ciphertext": payload["ciphertext"],
                "burn_on_read": payload.get("burn_on_read", True),
                "expires_at": payload["expires_at"],
                "allow_ip": payload.get("allow_ip"),
                "created_at": payload.get("created_at", int(time.time())),
            }
        return {
            "id": secret_id,
            "expires_at": payload["expires_at"],
            "burn_on_read": payload.get("burn_on_read", True),
        }

    def get(self, secret_id: str, client_ip: Optional[str] = None) -> Optional[dict[str, Any]]:
        """
        Retrieve and optionally burn a secret.
        Returns None if not found or expired.
        Raises PermissionError if client_ip violates allow_ip.
        """
        now = int(time.time())
        with self._lock:
            self._purge_expired_locked()
            record = self._store.get(secret_id)
            if not record:
                return None

            if now >= record["expires_at"]:
                self._store.pop(secret_id, None)
                return None

            # IP Allowlist verification
            allow_ip = record.get("allow_ip")
            if allow_ip and client_ip:
                if client_ip != allow_ip and not client_ip.startswith(allow_ip.rstrip("*")):
                    raise PermissionError(f"Access denied: Client IP '{client_ip}' is not authorized for this secret.")

            # Burn-on-read
            burn = record.get("burn_on_read", True)
            if burn:
                self._store.pop(secret_id, None)

            return {
                "id": record["id"],
                "ciphertext": record["ciphertext"],
                "burn_on_read": burn,
                "expires_at": record["expires_at"],
            }

    def _purge_expired_locked(self) -> int:
        now = int(time.time())
        expired = [sid for sid, rec in self._store.items() if now >= rec["expires_at"]]
        for sid in expired:
            self._store.pop(sid, None)
        return len(expired)

    def count(self) -> int:
        with self._lock:
            self._purge_expired_locked()
            return len(self._store)


# Global singleton instance for the process
GLOBAL_VAULT = VaultStore()
