"""Authenticated encryption primitives (libsodium ``crypto_secretbox``).

Thin wrappers around :class:`nacl.secret.SecretBox` that (a) split the nonce from the
ciphertext for separate storage, matching the server's ``nonce_*`` / ``wrapped_*`` /
``blob`` fields, and (b) translate libsodium failures into :class:`DecryptionError`.
"""

from __future__ import annotations

from nacl.exceptions import CryptoError as NaClCryptoError
from nacl.secret import SecretBox
from nacl.utils import random as random_bytes

from dotmage.core.crypto import suite
from dotmage.exceptions import DecryptionError


def encrypt(key: bytes, plaintext: bytes, *, nonce: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt ``plaintext`` under ``key``.

    Args:
        key: A 32-byte symmetric key.
        plaintext: The data to encrypt.
        nonce: Optional explicit 24-byte nonce (a random one is generated otherwise).

    Returns:
        A ``(nonce, ciphertext)`` tuple, where ``ciphertext`` includes the Poly1305 tag.
    """
    box = SecretBox(key)
    used_nonce = nonce if nonce is not None else random_bytes(suite.NONCE_BYTES)
    encrypted = box.encrypt(plaintext, used_nonce)
    return encrypted.nonce, encrypted.ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt and authenticate ``ciphertext``.

    Args:
        key: The 32-byte symmetric key.
        nonce: The 24-byte nonce used at encryption time.
        ciphertext: The ciphertext (with tag) produced by :func:`encrypt`.

    Returns:
        The recovered plaintext.

    Raises:
        DecryptionError: If authentication fails (wrong key or tampered data).
    """
    box = SecretBox(key)
    try:
        return box.decrypt(ciphertext, nonce)
    except NaClCryptoError as exc:
        raise DecryptionError("authenticated decryption failed") from exc
