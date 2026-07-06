"""The frozen cryptographic contract for dotMage.

Every algorithm choice, size, version and encoding the SDK relies on lives here so it can be
audited and, if needed, aligned with the reference ``dmage`` client / ``dotmage-spec`` in one
place. Changing any value here changes the on-the-wire format and breaks compatibility.

Profile (libsodium via PyNaCl):

* KDF: ``crypto_pwhash`` with ``ALG_ARGON2ID13`` (``argon_version = 19``). ``memlimit`` is in
  **bytes** (= ``argon_memory`` KiB * 1024); ``opslimit`` = ``argon_iterations``; parallelism
  is fixed to 1 by libsodium (matching the server's default ``argon_parallelism = 1``).
* AEAD: ``crypto_secretbox`` (XSalsa20-Poly1305), 24-byte nonces, 32-byte keys.
* Blob envelope: ``version(1) || nonce(24) || ciphertext``, base64 (standard) encoded.
* Invitation sealing: ``crypto_secretbox`` under a key derived from the redeem secret.

.. warning::
   Byte-level interoperability with the ``dmage`` CLI is **not yet verified**. See
   ``docs/crypto.md`` and ``tests/test_crypto_vectors.py``. Treat these constants as the
   contract to reconcile against ``dotmage-spec`` before a production release.
"""

from __future__ import annotations

import base64

# --- KDF (Argon2id) ------------------------------------------------------- #
KDF_NAME = "argon2id"
ARGON_VERSION = 19  # 0x13 == Argon2 v1.3 == libsodium ALG_ARGON2ID13
DEFAULT_ARGON_MEMORY_KIB = 65536  # 64 MiB
DEFAULT_ARGON_ITERATIONS = 3
DEFAULT_ARGON_PARALLELISM = 1
KIB = 1024

# --- Sizes (bytes) -------------------------------------------------------- #
KEK_BYTES = 32
ACCOUNT_KEY_BYTES = 32
SALT_BYTES = 16  # libsodium crypto_pwhash_SALTBYTES
NONCE_BYTES = 24  # libsodium crypto_secretbox_NONCEBYTES
RECOVERY_CODE_BYTES = 20  # 160 bits of entropy -> 32 base32 chars

# --- Blob envelope -------------------------------------------------------- #
BLOB_VERSION = 1


def memlimit_bytes(memory_kib: int) -> int:
    """Convert an Argon2 memory cost in KiB to libsodium's ``memlimit`` in bytes."""
    return memory_kib * KIB


def b64encode(data: bytes) -> str:
    """Standard base64 encode to an ASCII string."""
    return base64.b64encode(data).decode("ascii")


def b64decode(text: str) -> bytes:
    """Standard base64 decode from an ASCII string."""
    return base64.b64decode(text.encode("ascii"))
