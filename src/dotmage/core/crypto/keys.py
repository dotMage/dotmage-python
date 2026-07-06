"""Account key (AK) generation, wrapping, and unwrapping.

The AK is a random 32-byte symmetric key shared across an account/team and used to encrypt
every config blob. It is stored on the server only in *wrapped* form: encrypted under a KEK
derived from a master password (and optionally, separately, from a recovery code).
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass

from nacl.utils import random as random_bytes

from dotmage.core.crypto import aead, suite
from dotmage.core.crypto.kdf import derive_kek
from dotmage.exceptions import DecryptionError, MasterPasswordError


@dataclass(frozen=True)
class KeyMaterial:
    """The wrapped-key fields the server stores and returns (all base64 where binary).

    Mirrors ``AccountInitRequest`` / ``GET /account/keys`` fields one-to-one.
    """

    salt: str
    argon_memory: int
    argon_iterations: int
    argon_parallelism: int
    argon_version: int
    nonce_ak: str
    wrapped_ak: str
    salt_rc: str | None = None
    nonce_rc: str | None = None
    wrapped_ak_rc: str | None = None


@dataclass(frozen=True)
class AccountKeyCreation:
    """Result of creating a brand-new account key."""

    material: KeyMaterial
    account_key: bytes
    recovery_code: str | None


def generate_account_key() -> bytes:
    """Return a fresh random account key."""
    return random_bytes(suite.ACCOUNT_KEY_BYTES)


def generate_salt() -> bytes:
    """Return a fresh random KDF salt."""
    return random_bytes(suite.SALT_BYTES)


def generate_recovery_code() -> str:
    """Return a human-transcribable recovery code (base32, grouped in fives)."""
    raw = secrets.token_bytes(suite.RECOVERY_CODE_BYTES)
    text = base64.b32encode(raw).decode("ascii").rstrip("=")
    return "-".join(text[i : i + 5] for i in range(0, len(text), 5))


def normalize_recovery_code(code: str) -> str:
    """Normalise a recovery code for KDF input (uppercase, no separators/whitespace)."""
    return "".join(code.split()).replace("-", "").upper()


def _wrap(ak: bytes, password: str, *, memory_kib: int, iterations: int) -> tuple[str, str, str]:
    """Wrap ``ak`` under a KEK derived from ``password``. Returns (salt, nonce, wrapped)."""
    salt = generate_salt()
    kek = derive_kek(password, salt, memory_kib=memory_kib, iterations=iterations)
    nonce, ciphertext = aead.encrypt(kek, ak)
    return suite.b64encode(salt), suite.b64encode(nonce), suite.b64encode(ciphertext)


def build_key_material(
    ak: bytes,
    password: str,
    *,
    with_recovery: bool = True,
    memory_kib: int = suite.DEFAULT_ARGON_MEMORY_KIB,
    iterations: int = suite.DEFAULT_ARGON_ITERATIONS,
) -> tuple[KeyMaterial, str | None]:
    """Wrap an existing AK into a full :class:`KeyMaterial` bundle (with optional recovery).

    Returns the material and the generated recovery code (``None`` when ``with_recovery`` is
    false). Used both for a fresh account and when an invitee re-wraps a sealed AK.
    """
    salt, nonce_ak, wrapped_ak = _wrap(ak, password, memory_kib=memory_kib, iterations=iterations)

    salt_rc = nonce_rc = wrapped_ak_rc = None
    recovery_code: str | None = None
    if with_recovery:
        recovery_code = generate_recovery_code()
        salt_rc, nonce_rc, wrapped_ak_rc = _wrap(
            ak,
            normalize_recovery_code(recovery_code),
            memory_kib=memory_kib,
            iterations=iterations,
        )

    material = KeyMaterial(
        salt=salt,
        argon_memory=memory_kib,
        argon_iterations=iterations,
        argon_parallelism=suite.DEFAULT_ARGON_PARALLELISM,
        argon_version=suite.ARGON_VERSION,
        nonce_ak=nonce_ak,
        wrapped_ak=wrapped_ak,
        salt_rc=salt_rc,
        nonce_rc=nonce_rc,
        wrapped_ak_rc=wrapped_ak_rc,
    )
    return material, recovery_code


def create_account_key_material(
    password: str,
    *,
    with_recovery: bool = True,
    memory_kib: int = suite.DEFAULT_ARGON_MEMORY_KIB,
    iterations: int = suite.DEFAULT_ARGON_ITERATIONS,
) -> AccountKeyCreation:
    """Generate a new AK and wrap it under the master password (and optional recovery code)."""
    ak = generate_account_key()
    material, recovery_code = build_key_material(
        ak, password, with_recovery=with_recovery, memory_kib=memory_kib, iterations=iterations
    )
    return AccountKeyCreation(material=material, account_key=ak, recovery_code=recovery_code)


def rewrap_account_key(
    ak: bytes,
    password: str,
    *,
    memory_kib: int = suite.DEFAULT_ARGON_MEMORY_KIB,
    iterations: int = suite.DEFAULT_ARGON_ITERATIONS,
) -> tuple[str, str, str]:
    """Re-wrap an existing AK under a (new) master password. Returns (salt, nonce, wrapped)."""
    return _wrap(ak, password, memory_kib=memory_kib, iterations=iterations)


def wrap_with_salt(
    ak: bytes,
    password: str,
    *,
    salt: str,
    memory_kib: int,
    iterations: int,
) -> tuple[str, str]:
    """Wrap an AK under a KEK derived from ``password`` and an *existing* salt.

    Used by key rotation, whose ``begin`` request re-wraps the AK but does not carry a new
    ``salt`` field. Returns ``(nonce_ak, wrapped_ak)`` as base64 strings.
    """
    kek = derive_kek(password, suite.b64decode(salt), memory_kib=memory_kib, iterations=iterations)
    nonce, ciphertext = aead.encrypt(kek, ak)
    return suite.b64encode(nonce), suite.b64encode(ciphertext)


def unwrap_account_key(
    password: str,
    *,
    salt: str,
    nonce_ak: str,
    wrapped_ak: str,
    argon_memory: int,
    argon_iterations: int,
) -> bytes:
    """Recover the AK from its master-password wrap.

    Raises:
        MasterPasswordError: If the password is wrong (authentication fails).
    """
    kek = derive_kek(
        password,
        suite.b64decode(salt),
        memory_kib=argon_memory,
        iterations=argon_iterations,
    )
    try:
        return aead.decrypt(kek, suite.b64decode(nonce_ak), suite.b64decode(wrapped_ak))
    except DecryptionError as exc:
        raise MasterPasswordError("wrong master password") from exc


def unwrap_account_key_with_recovery(
    recovery_code: str,
    *,
    salt_rc: str | None,
    nonce_rc: str | None,
    wrapped_ak_rc: str | None,
    argon_memory: int,
    argon_iterations: int,
) -> bytes:
    """Recover the AK from its recovery-code wrap.

    Raises:
        MasterPasswordError: If no recovery wrap exists or the code is wrong.
    """
    if not (salt_rc and nonce_rc and wrapped_ak_rc):
        raise MasterPasswordError("no recovery wrap is configured for this account")
    kek = derive_kek(
        normalize_recovery_code(recovery_code),
        suite.b64decode(salt_rc),
        memory_kib=argon_memory,
        iterations=argon_iterations,
    )
    try:
        return aead.decrypt(kek, suite.b64decode(nonce_rc), suite.b64decode(wrapped_ak_rc))
    except DecryptionError as exc:
        raise MasterPasswordError("wrong recovery code") from exc
