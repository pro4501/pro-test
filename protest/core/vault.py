"""Encryption of stored passwords and tokens (standard library only).

WHY
    The central database keeps credentials: the ones you give Pro-Test for authenticated scans and
    the weak logins a scan discovers. They must not be readable by someone who only gets a copy of
    the .db file, so the secret part is encrypted with a key kept in a SEPARATE file.

HOW (authenticated encryption, "encrypt-then-MAC")
    master key  32 random bytes in ~/.pro-test/protest.key (created on first use)
    sub-keys    enc_key = HMAC(master, "enc"), mac_key = HMAC(master, "mac")  (never reuse one key
                for two purposes)
    encrypt     nonce   = 16 random bytes (a new one for every value)
                stream  = HMAC-SHA256(enc_key, nonce || counter) for counter = 0, 1, 2...
                cipher  = plaintext XOR stream                       (a stream cipher in counter mode)
                tag     = HMAC-SHA256(mac_key, version || nonce || cipher)
                token   = "pt1:" + base64(nonce || cipher || tag)
    decrypt     recompute the tag and compare it in constant time (hmac.compare_digest) BEFORE
                decrypting: a modified token is rejected instead of silently decrypting to garbage.

    HMAC-SHA256 is a pseudo-random function, so this is a sound construction, but it is home-made:
    the standard library has no AES. For production software prefer a reviewed library such as
    `cryptography` (Fernet / AES-GCM).

LIMITS
    Anyone who has BOTH the database and the key file can decrypt. Keep the key file private, don't
    copy it with the database, and on shared machines protect your user profile.
"""
import base64
import hashlib
import hmac
import os
import secrets

TOKEN_PREFIX = "pt1:"
NONCE_SIZE = 16
TAG_SIZE = 32
KEY_SIZE = 32


class VaultError(ValueError):
    """The token is malformed, was modified, or was encrypted with another key."""


class Vault:
    def __init__(self, key_path: str):
        self.key_path = key_path
        master = self._load_or_create_key(key_path)
        self._enc_key = hmac.new(master, b"pro-test enc", hashlib.sha256).digest()
        self._mac_key = hmac.new(master, b"pro-test mac", hashlib.sha256).digest()

    @staticmethod
    def _load_or_create_key(path: str) -> bytes:
        if os.path.exists(path):
            with open(path, "rb") as handle:
                key = base64.b64decode(handle.read().strip())
            if len(key) != KEY_SIZE:
                raise VaultError(f"Key file {path} is corrupted")
            return key
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        key = secrets.token_bytes(KEY_SIZE)
        # O_EXCL: never overwrite a key created at the same moment by another process
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(base64.b64encode(key))
        return key

    def _keystream(self, nonce: bytes, length: int) -> bytes:
        blocks = []
        for counter in range((length + 31) // 32):
            blocks.append(hmac.new(self._enc_key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest())
        return b"".join(blocks)[:length]

    def encrypt(self, plaintext: str) -> str:
        data = plaintext.encode("utf-8")
        nonce = secrets.token_bytes(NONCE_SIZE)
        cipher = bytes(a ^ b for a, b in zip(data, self._keystream(nonce, len(data))))
        tag = hmac.new(self._mac_key, TOKEN_PREFIX.encode() + nonce + cipher, hashlib.sha256).digest()
        return TOKEN_PREFIX + base64.b64encode(nonce + cipher + tag).decode("ascii")

    def decrypt(self, token: str) -> str:
        if not token or not token.startswith(TOKEN_PREFIX):
            raise VaultError("Not a Pro-Test encrypted value")
        try:
            raw = base64.b64decode(token[len(TOKEN_PREFIX):], validate=True)
        except (ValueError, TypeError) as error:
            raise VaultError("Malformed encrypted value") from error
        if len(raw) < NONCE_SIZE + TAG_SIZE:
            raise VaultError("Malformed encrypted value")
        nonce, cipher, tag = raw[:NONCE_SIZE], raw[NONCE_SIZE:-TAG_SIZE], raw[-TAG_SIZE:]
        expected = hmac.new(self._mac_key, TOKEN_PREFIX.encode() + nonce + cipher, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise VaultError("Integrity check failed: wrong key or modified value")
        return bytes(a ^ b for a, b in zip(cipher, self._keystream(nonce, len(cipher)))).decode("utf-8")
