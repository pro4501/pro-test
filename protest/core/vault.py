# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Encryption of stored passwords and tokens.

New secrets use the cryptography library's Fernet format (AES-128 in CBC with
HMAC-SHA256). The 32-byte key file is unchanged. A Fernet key is derived from
it with HKDF so the raw key bytes are not the token key.

Tokens look like "pt2:" plus the Fernet token. Tokens that start with "pt1:"
were written by the previous home-grown construction. They are not decrypted
and they are not deleted. Enter the secret again if you still need it.

Anyone who has both the database and the key file can decrypt. Keep the key
file private.
"""
import base64
import os
import secrets

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from protest.core.paths import ensure_private_dir, tighten_file

TOKEN_PREFIX = "pt2:"
LEGACY_PREFIX = "pt1:"
KEY_SIZE = 32
_HKDF_SALT = b"pro-test-vault"
_HKDF_INFO = b"fernet-v1"


class VaultError(Exception):
    """The secret cannot be decrypted with this key."""


class VaultLegacyError(VaultError):
    """The row uses the old pt1: construction and was left unchanged."""


class Vault:
    def __init__(self, path: str):
        self.path = path
        self._master = self._load_or_create()

    def _load_or_create(self) -> bytes:
        if os.path.exists(self.path):
            with open(self.path, "rb") as handle:
                key = handle.read()
            if len(key) != KEY_SIZE:
                raise VaultError(f"Key file {self.path} is not {KEY_SIZE} bytes")
            tighten_file(self.path)
            return key
        folder = os.path.dirname(os.path.abspath(self.path))
        ensure_private_dir(folder)
        key = secrets.token_bytes(KEY_SIZE)
        with open(self.path, "wb") as handle:
            handle.write(key)
        tighten_file(self.path)
        return key

    def _fernet(self) -> Fernet:
        derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=_HKDF_SALT, info=_HKDF_INFO).derive(self._master)
        return Fernet(base64.urlsafe_b64encode(derived))

    def encrypt(self, plaintext: str) -> str:
        token = self._fernet().encrypt(plaintext.encode("utf-8"))
        return TOKEN_PREFIX + token.decode("ascii")

    def decrypt(self, token: str) -> str:
        if token.startswith(LEGACY_PREFIX):
            raise VaultLegacyError(
                "This secret was stored as pt1: and was not decrypted. The ciphertext is still in the database. "
                "Enter the secret again so it can be stored with the current encryption."
            )
        if not token.startswith(TOKEN_PREFIX):
            raise VaultError("Unrecognised credential token")
        try:
            raw = self._fernet().decrypt(token[len(TOKEN_PREFIX):].encode("ascii"))
        except (InvalidToken, ValueError) as exception:
            raise VaultError("Credential token failed authentication") from exception
        return raw.decode("utf-8")
