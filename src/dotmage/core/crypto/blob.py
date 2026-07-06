"""Encrypt/decrypt an environment dict into the stored ``blob``.

Envelope: ``version(1 byte) || nonce(24) || ciphertext``, base64 encoded. The plaintext is a
canonical JSON object (sorted keys, compact separators) so ``content_hash`` is stable across
clients. ``content_hash`` = SHA-256 hex of that canonical plaintext; the server stores it but
does not validate it — integrity is guaranteed by the AEAD tag.
"""

from __future__ import annotations

import hashlib
import json

from dotmage.core.crypto import aead, suite
from dotmage.exceptions import ContentIntegrityError, InteropError


def canonical_bytes(data: dict[str, str]) -> bytes:
    """Serialise an env dict to canonical JSON bytes (sorted keys, compact, UTF-8)."""
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def content_hash(data: dict[str, str]) -> str:
    """Return the SHA-256 hex digest of the canonical plaintext for ``data``."""
    return hashlib.sha256(canonical_bytes(data)).hexdigest()


def encrypt_blob(account_key: bytes, data: dict[str, str]) -> tuple[str, str]:
    """Encrypt ``data`` under the account key.

    Returns:
        ``(blob, content_hash)`` where ``blob`` is the base64 envelope string.
    """
    plaintext = canonical_bytes(data)
    nonce, ciphertext = aead.encrypt(account_key, plaintext)
    envelope = bytes([suite.BLOB_VERSION]) + nonce + ciphertext
    return suite.b64encode(envelope), hashlib.sha256(plaintext).hexdigest()


def decrypt_blob(account_key: bytes, blob: str) -> dict[str, str]:
    """Decrypt a stored ``blob`` back into an env dict.

    Raises:
        InteropError: If the envelope version/format is not understood.
        DecryptionError: If authentication fails (wrong key or tampered data).
    """
    envelope = suite.b64decode(blob)
    if len(envelope) < 1 + suite.NONCE_BYTES:
        raise InteropError("blob envelope is too short")
    version = envelope[0]
    if version != suite.BLOB_VERSION:
        raise InteropError(f"unsupported blob version: {version}")
    nonce = envelope[1 : 1 + suite.NONCE_BYTES]
    ciphertext = envelope[1 + suite.NONCE_BYTES :]
    plaintext = aead.decrypt(account_key, nonce, ciphertext)
    loaded = json.loads(plaintext.decode("utf-8"))
    if not isinstance(loaded, dict):
        raise InteropError("decrypted blob is not a JSON object")
    return {str(k): str(v) for k, v in loaded.items()}


def verify_content_hash(data: dict[str, str], expected: str | None) -> None:
    """Check a decrypted dict against an expected ``content_hash``.

    A ``None`` expected value is treated as "not provided" and passes.

    Raises:
        ContentIntegrityError: If the hashes differ.
    """
    if expected is None:
        return
    actual = content_hash(data)
    if actual != expected:
        raise ContentIntegrityError(f"content hash mismatch (expected {expected}, got {actual})")
