"""Key derivation: master password -> key-encryption key (KEK).

Uses libsodium's Argon2id (``ALG_ARGON2ID13``). The server stores the parameters
(``salt``, ``argon_memory``, ``argon_iterations``, ``argon_version``) and hands them back on
unlock; it never runs the KDF itself.
"""

from __future__ import annotations

from nacl.pwhash import argon2id

from dotmage.core.crypto import suite


def derive_kek(
    password: str,
    salt: bytes,
    *,
    memory_kib: int = suite.DEFAULT_ARGON_MEMORY_KIB,
    iterations: int = suite.DEFAULT_ARGON_ITERATIONS,
    size: int = suite.KEK_BYTES,
) -> bytes:
    """Derive a key-encryption key from a master password.

    Args:
        password: The user's master password (or recovery code).
        salt: A ``SALT_BYTES``-long salt.
        memory_kib: Argon2 memory cost in KiB (``opslimit`` companion).
        iterations: Argon2 iteration count (``opslimit``).
        size: Output key length in bytes.

    Returns:
        The derived key.

    Raises:
        ValueError: If the salt length is wrong.
    """
    if len(salt) != suite.SALT_BYTES:
        msg = f"salt must be {suite.SALT_BYTES} bytes, got {len(salt)}"
        raise ValueError(msg)
    return argon2id.kdf(
        size,
        password.encode("utf-8"),
        salt,
        opslimit=iterations,
        memlimit=suite.memlimit_bytes(memory_kib),
    )
