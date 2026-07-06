"""In-memory session state: the unlocked account key and its generation.

The account key (AK) is never written to disk. It lives here for the lifetime of an unlocked
client and is used to encrypt/decrypt config blobs.
"""

from __future__ import annotations

from dotmage.core.crypto import blob
from dotmage.exceptions import LockedError


class Session:
    """Holds the decrypted account key while a client is unlocked."""

    def __init__(self) -> None:
        self._account_key: bytes | None = None
        self._key_gen: int | None = None

    @property
    def is_unlocked(self) -> bool:
        return self._account_key is not None

    @property
    def account_key(self) -> bytes:
        if self._account_key is None:
            raise LockedError("session is locked — call unlock() first")
        return self._account_key

    @property
    def key_gen(self) -> int:
        if self._key_gen is None:
            raise LockedError("session is locked — call unlock() first")
        return self._key_gen

    def set_key(self, account_key: bytes, key_gen: int) -> None:
        """Store the unlocked account key and its generation."""
        self._account_key = account_key
        self._key_gen = key_gen

    def clear(self) -> None:
        """Forget the account key (lock the session)."""
        self._account_key = None
        self._key_gen = None

    def encrypt(self, data: dict[str, str]) -> tuple[str, str]:
        """Encrypt an env dict; returns ``(blob, content_hash)``."""
        return blob.encrypt_blob(self.account_key, data)

    def decrypt(self, ciphertext: str) -> dict[str, str]:
        """Decrypt a stored blob back into an env dict."""
        return blob.decrypt_blob(self.account_key, ciphertext)
