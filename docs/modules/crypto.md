# Module: `dotmage.core.crypto`

The `core.crypto` package is the entire client-side cryptography of the SDK: key derivation,
account-key generation and wrapping, blob encryption with a versioned envelope, and
domain-separated sealing for team invitations. Every constant and algorithm choice is pinned
in one place (`suite.py`) so the wire format can be audited and reconciled against the
reference `dmage` client.

This page documents the public symbols. For the full byte-level specification and the
**interoperability status**, read the [cryptographic contract](../crypto.md). For why the
server can store all of this without reading it, see the
[security model](../security-model.md).

> **Interoperability:** byte-compatibility with `dmage` is **not yet verified** — see
> [crypto contract → Interoperability status](../crypto.md#interoperability-status).

## `suite` — the frozen contract

Constants only; the single source of truth. Key values:

| Name | Value | Meaning |
|------|-------|---------|
| `ARGON_VERSION` | `19` | Argon2id v1.3 (`ALG_ARGON2ID13`) |
| `DEFAULT_ARGON_MEMORY_KIB` | `65536` | 64 MiB memory cost |
| `DEFAULT_ARGON_ITERATIONS` | `3` | opslimit |
| `DEFAULT_ARGON_PARALLELISM` | `1` | fixed by libsodium |
| `KEK_BYTES` / `ACCOUNT_KEY_BYTES` | `32` | symmetric key sizes |
| `SALT_BYTES` | `16` | KDF salt |
| `NONCE_BYTES` | `24` | SecretBox nonce |
| `RECOVERY_CODE_BYTES` | `20` | 160-bit recovery entropy |
| `BLOB_VERSION` | `1` | blob envelope version byte |

Helpers: `memlimit_bytes(memory_kib) -> int` (KiB → bytes), `b64encode(bytes) -> str`,
`b64decode(str) -> bytes` (standard base64).

## `kdf` — key derivation

```python
derive_kek(password, salt, *, memory_kib=65536, iterations=3, size=32) -> bytes
```

Derives a KEK from a master password (or normalised recovery code) using libsodium Argon2id.
`memlimit = memory_kib * 1024`, `opslimit = iterations`. Raises `ValueError` if `salt` is not
`SALT_BYTES` long. See [contract → key derivation](../crypto.md#key-derivation-argon2id).

## `aead` — authenticated encryption

```python
encrypt(key, plaintext, *, nonce=None) -> tuple[bytes, bytes]   # (nonce, ciphertext+tag)
decrypt(key, nonce, ciphertext) -> bytes                        # raises DecryptionError
```

Thin wrappers over `nacl.secret.SecretBox` (XSalsa20-Poly1305). The nonce is returned
separately so it can be stored in the server's dedicated `nonce_*` fields. Decryption failure
maps to [`DecryptionError`](exceptions.md).

## `keys` — account key lifecycle

Dataclasses:

- `KeyMaterial` — the wrapped-key bundle the server stores/returns (mirrors
  `AccountInitRequest` / `GET /account/keys`): `salt, argon_memory, argon_iterations,
  argon_parallelism, argon_version, nonce_ak, wrapped_ak`, plus optional `salt_rc, nonce_rc,
  wrapped_ak_rc`.
- `AccountKeyCreation` — `material: KeyMaterial`, `account_key: bytes`, `recovery_code: str | None`.

Functions:

```python
generate_account_key() -> bytes
generate_salt() -> bytes
generate_recovery_code() -> str            # base32, grouped in fives
normalize_recovery_code(code) -> str       # uppercase, strip separators/whitespace
build_key_material(ak, password, *, with_recovery=True, memory_kib=65536, iterations=3)
    -> tuple[KeyMaterial, str | None]
create_account_key_material(password, *, with_recovery=True, memory_kib=65536, iterations=3)
    -> AccountKeyCreation
rewrap_account_key(ak, password, *, memory_kib=65536, iterations=3) -> tuple[str, str, str]
    # (salt, nonce, wrapped)
wrap_with_salt(ak, password, *, salt, memory_kib, iterations) -> tuple[str, str]
    # (nonce_ak, wrapped_ak) under an existing salt — used by rotation
unwrap_account_key(password, *, salt, nonce_ak, wrapped_ak, argon_memory, argon_iterations)
    -> bytes                               # raises MasterPasswordError on wrong password
unwrap_account_key_with_recovery(recovery_code, *, salt_rc, nonce_rc, wrapped_ak_rc,
    argon_memory, argon_iterations) -> bytes
```

See [contract → account key wrapping](../crypto.md#account-key-wrapping).

## `blob` — env dict ⇄ stored blob

```python
canonical_bytes(data) -> bytes             # sorted keys, compact, UTF-8
content_hash(data) -> str                  # sha256 hex of canonical plaintext
encrypt_blob(account_key, data) -> tuple[str, str]   # (base64 envelope, content_hash)
decrypt_blob(account_key, blob) -> dict[str, str]    # raises InteropError / DecryptionError
verify_content_hash(data, expected) -> None          # raises ContentIntegrityError
```

Envelope: `version(1) ‖ nonce(24) ‖ ciphertext`, base64. The server stores `content_hash` but
does not validate it. See [contract → blob envelope](../crypto.md#blob-envelope).

## `invitation` — sealed AK for team joins

```python
generate_redeem_secret() -> str            # url-safe token
redeem_hash(redeem_secret) -> str          # sha256 hex; matches server-stored hash
seal_account_key(account_key, redeem_secret) -> tuple[str, str]   # (nonce_inv, sealed_ak)
open_account_key(sealed_ak, nonce_inv, redeem_secret) -> bytes    # raises DecryptionError
```

The sealing key is `sha256(b"dotmage/invite/seal/v1\x00" || redeem_secret)` — **domain-separated**
from `redeem_hash` so the server cannot derive it. See
[contract → invitation sealing](../crypto.md#invitation-sealing).

## Example

The clients call these for you, but the primitives round-trip standalone:

```python
from dotmage.core.crypto import keys, blob

creation = keys.create_account_key_material("correct horse battery staple")
ak = creation.account_key

envelope, chash = blob.encrypt_blob(ak, {"API_KEY": "secret"})
assert blob.decrypt_blob(ak, envelope) == {"API_KEY": "secret"}

recovered = keys.unwrap_account_key(
    "correct horse battery staple",
    salt=creation.material.salt,
    nonce_ak=creation.material.nonce_ak,
    wrapped_ak=creation.material.wrapped_ak,
    argon_memory=creation.material.argon_memory,
    argon_iterations=creation.material.argon_iterations,
)
assert recovered == ak
```

## References

- [Cryptographic contract](../crypto.md) — the exhaustive spec and interop status.
- [security model](../security-model.md) — trust boundaries.
- [`session`](session.md) — holds the AK and calls `blob.encrypt_blob` / `decrypt_blob`.
- [`exceptions`](exceptions.md) — `DecryptionError`, `MasterPasswordError`,
  `ContentIntegrityError`, `InteropError`.
- Backend: `Account` / `User` wrapped-key + KDF fields, `Revision.blob` / `content_hash` /
  `key_gen`, `Invitation.sealed_ak` / `nonce_inv` / `redeem_hash` in
  `server/src/models/base.py`; endpoints `POST /account/init`, `GET /account/keys`,
  `POST /invitations/redeem`, `POST /invitations/complete`.
