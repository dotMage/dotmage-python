"""Sealing the account key for team invitations.

The inviter seals the AK under a key derived from a shared ``redeem_secret`` (delivered
out-of-band, e.g. via a link or QR code). The server stores ``sealed_ak`` + ``nonce_inv`` and
only hands them out after verifying ``sha256(redeem_secret) == redeem_hash`` — but it can
never open them, because the sealing key is domain-separated from ``redeem_hash``.
"""

from __future__ import annotations

import hashlib
import secrets

from dotmage.core.crypto import aead, suite

# Domain-separation prefix: the sealing key must NOT be derivable from ``redeem_hash``
# (which the server stores), so we hash the secret under a distinct label.
_SEAL_LABEL = b"dotmage/invite/seal/v1\x00"


def generate_redeem_secret() -> str:
    """Return a fresh, URL-safe redeem secret to share with the invitee."""
    return secrets.token_urlsafe(32)


def redeem_hash(redeem_secret: str) -> str:
    """SHA-256 hex of the redeem secret (matches the server's ``sha256_hash``)."""
    return hashlib.sha256(redeem_secret.encode("utf-8")).hexdigest()


def _seal_key(redeem_secret: str) -> bytes:
    return hashlib.sha256(_SEAL_LABEL + redeem_secret.encode("utf-8")).digest()


def seal_account_key(account_key: bytes, redeem_secret: str) -> tuple[str, str]:
    """Seal the AK for an invitee. Returns ``(nonce_inv, sealed_ak)`` as base64 strings."""
    nonce, ciphertext = aead.encrypt(_seal_key(redeem_secret), account_key)
    return suite.b64encode(nonce), suite.b64encode(ciphertext)


def open_account_key(sealed_ak: str, nonce_inv: str, redeem_secret: str) -> bytes:
    """Open a sealed AK using the shared redeem secret.

    Raises:
        DecryptionError: If the secret is wrong or the data was tampered with.
    """
    return aead.decrypt(
        _seal_key(redeem_secret),
        suite.b64decode(nonce_inv),
        suite.b64decode(sealed_ak),
    )
