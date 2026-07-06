# Cryptographic contract

This page is the precise specification of dotMage's client-side cryptography as implemented by
this SDK. The single source of truth for every constant is
[`src/dotmage/core/crypto/suite.py`](modules/crypto.md); the algorithms live in the sibling
modules `kdf.py`, `aead.py`, `keys.py`, `blob.py`, and `invitation.py`.

Everything here runs locally. The server never performs any of these operations — see the
[security model](security-model.md).

> **Interoperability status — read this first.** See the
> [Interoperability status](#interoperability-status) section below: byte-level compatibility
> with the reference `dmage` CLI is **not yet verified**. The contract on this page is the
> *declared* wire format, to be reconciled against `dotmage-spec` via test vectors before any
> production release.

## Profile at a glance

All primitives come from libsodium via **PyNaCl**.

| Component | Choice |
|-----------|--------|
| KDF | Argon2id (`crypto_pwhash`, `ALG_ARGON2ID13`) |
| Argon version | `19` (0x13 = Argon2 v1.3) |
| Default memory | `65536` KiB (64 MiB) |
| Default iterations | `3` |
| Parallelism | `1` (fixed by libsodium) |
| AEAD | `crypto_secretbox` = XSalsa20-Poly1305 |
| Nonce size | 24 bytes |
| Symmetric key size | 32 bytes (KEK, AK) |
| Salt size | 16 bytes (`crypto_pwhash_SALTBYTES`) |
| Recovery code entropy | 20 bytes (160 bits) → base32 |
| Blob envelope version | `1` |
| Binary encoding | standard base64 (`base64.b64encode`) |

Constants (`src/dotmage/core/crypto/suite.py`):

```python
ARGON_VERSION = 19
DEFAULT_ARGON_MEMORY_KIB = 65536   # 64 MiB
DEFAULT_ARGON_ITERATIONS = 3
DEFAULT_ARGON_PARALLELISM = 1
KIB = 1024
KEK_BYTES = 32
ACCOUNT_KEY_BYTES = 32
SALT_BYTES = 16
NONCE_BYTES = 24
RECOVERY_CODE_BYTES = 20
BLOB_VERSION = 1
```

## Key derivation (Argon2id)

`kdf.derive_kek(password, salt, *, memory_kib, iterations, size)` derives a key-encryption key
from a master password (or a normalised recovery code):

- Algorithm: `nacl.pwhash.argon2id.kdf`, i.e. libsodium `crypto_pwhash` with
  `ALG_ARGON2ID13` → **`argon_version = 19`**.
- **`memlimit` is in bytes**: `memlimit = memory_kib * 1024` (`suite.memlimit_bytes`). The
  server stores and returns the cost in **KiB** (`argon_memory`); the SDK multiplies by 1024.
- **`opslimit = iterations`** (`argon_iterations`).
- **Parallelism is fixed to 1** by libsodium's `crypto_pwhash`, matching the server default
  `argon_parallelism = 1`.
- `size` defaults to `KEK_BYTES` (32). Output is the raw derived key.
- The salt must be exactly `SALT_BYTES` (16) bytes or `ValueError` is raised.

The KDF parameters (`salt`, `argon_memory`, `argon_iterations`, `argon_version`,
`argon_parallelism`) are stored on the server and returned on unlock; the server itself never
runs the KDF. See `Account`/`User` fields in `server/src/models/base.py` and `GET
/api/v1/account/keys`.

## AEAD (SecretBox)

`aead.encrypt` / `aead.decrypt` wrap `nacl.secret.SecretBox` (XSalsa20-Poly1305):

- Key: 32 bytes. Nonce: 24 bytes (randomly generated per encryption unless supplied).
- `encrypt(key, plaintext)` returns `(nonce, ciphertext)` where `ciphertext` **includes the
  16-byte Poly1305 tag**. The nonce is returned separately so it can be stored in the
  server's dedicated `nonce_*` columns.
- `decrypt(key, nonce, ciphertext)` authenticates then decrypts; on any libsodium failure it
  raises [`DecryptionError`](modules/exceptions.md) ("authenticated decryption failed").

This is the single AEAD used everywhere: wrapping the AK, encrypting blobs, and sealing
invitations.

## Account key wrapping

The **account key (AK)** is a random 32-byte key (`keys.generate_account_key`). It is stored
only wrapped. `keys._wrap(ak, password, ...)` performs:

```
salt          = random(16)
kek           = Argon2id(password, salt, memory_kib, iterations)   # 32 bytes
nonce, ct     = SecretBox(kek).encrypt(ak)                         # ct includes tag
-> (b64(salt), b64(nonce), b64(ct))   == (salt, nonce_ak, wrapped_ak)
```

`keys.build_key_material(ak, password, with_recovery=...)` produces the full
[`KeyMaterial`](modules/crypto.md) bundle the server stores, matching `AccountInitRequest` /
`GET /api/v1/account/keys` field-for-field:

`salt, argon_memory, argon_iterations, argon_parallelism, argon_version, nonce_ak, wrapped_ak`,
and (when `with_recovery`) `salt_rc, nonce_rc, wrapped_ak_rc`.

- **Master-password wrap** → `salt` / `nonce_ak` / `wrapped_ak`.
- **Recovery wrap** → the *same AK* wrapped under a KEK derived from the normalised recovery
  code → `salt_rc` / `nonce_rc` / `wrapped_ak_rc`.
- `keys.wrap_with_salt(ak, password, *, salt, ...)` re-wraps under an *existing* salt (used by
  rotation's `begin`, which does not send a new `salt`).
- `keys.unwrap_account_key(...)` / `unwrap_account_key_with_recovery(...)` re-derive the KEK
  and AEAD-decrypt the wrap; a wrong secret raises
  [`MasterPasswordError`](modules/exceptions.md).

### Recovery code format

`keys.generate_recovery_code()` takes 20 random bytes (160 bits), base32-encodes them, strips
`=` padding, and groups the result into hyphen-separated blocks of five characters (e.g.
`ABCDE-FGHIJ-KLMNO-...`). `keys.normalize_recovery_code(code)` uppercases and removes
whitespace and hyphens before it is fed to the KDF — so display formatting is irrelevant to
derivation.

## Blob envelope

An environment dict is encrypted into the stored `blob` (`blob.encrypt_blob`):

```
plaintext  = canonical_json(dict)                 # see below
nonce, ct  = SecretBox(account_key).encrypt(plaintext)
envelope   = bytes([BLOB_VERSION]) || nonce(24) || ct
blob       = base64(envelope)
```

So the decoded envelope is exactly `version(1 byte) ‖ nonce(24 bytes) ‖ ciphertext(rest)`.

`blob.decrypt_blob(account_key, blob)` reverses it: base64-decode, check length
`>= 1 + 24`, verify `version == 1` (else [`InteropError`](modules/exceptions.md)), split off
the nonce, AEAD-decrypt, then JSON-parse. A non-object plaintext raises `InteropError`; all
keys and values are coerced to `str`.

### Canonical JSON and content hash

`blob.canonical_bytes(data)` serialises with:

```python
json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
```

That is: **UTF-8, keys sorted, compact separators (`,` and `:`), non-ASCII left as-is.** This
canonicalisation makes the plaintext — and therefore the content hash — stable across clients.

`content_hash = sha256(canonical_bytes(data))` as lowercase hex. It is returned alongside the
blob on push and stored in `Revision.content_hash`, but **the server does not validate it** —
integrity is guaranteed by the AEAD tag. Clients use it for drift/diff
([`core/diffing.py`](modules/models.md)) and, on pull with `verify=True`, to double-check the
decrypted plaintext via `blob.verify_content_hash` (mismatch →
[`ContentIntegrityError`](modules/exceptions.md)).

## Invitation sealing

For team invitations the inviter seals the AK under a key derived from a shared
`redeem_secret`, delivered to the invitee out of band. See
[`invitation.py`](modules/crypto.md) and the [security model](security-model.md#what-the-server-cannot-see).

```
redeem_secret = token_urlsafe(32)                                  # generate_redeem_secret
redeem_hash   = sha256(redeem_secret)                              # hex; stored server-side
seal_key      = sha256(b"dotmage/invite/seal/v1\x00" || redeem_secret)   # 32 bytes
nonce, ct     = SecretBox(seal_key).encrypt(account_key)
-> (b64(nonce), b64(ct))   == (nonce_inv, sealed_ak)
```

- **Domain separation is essential.** The server stores `redeem_hash = sha256(redeem_secret)`
  to gate who may fetch the sealed AK. The sealing key uses a *distinct labelled hash*
  (`_SEAL_LABEL = b"dotmage/invite/seal/v1\x00"`), so possessing `redeem_hash` does **not**
  let the server derive `seal_key` and open `sealed_ak`.
- `invitation.open_account_key(sealed_ak, nonce_inv, redeem_secret)` re-derives `seal_key` and
  AEAD-decrypts to recover the AK. The invitee then re-wraps that AK under their own master
  password via `keys.build_key_material` (this is what `join` does).

Backend fields: `Invitation.sealed_ak`, `Invitation.nonce_inv`, `Invitation.redeem_hash` in
`server/src/models/base.py`; endpoints `POST /api/v1/invitations/redeem` and
`POST /api/v1/invitations/complete`.

## Interoperability status

**Byte-level interoperability with the reference `dmage` CLI is NOT yet verified.**

The constants and formats above are the *declared* cryptographic contract, chosen to match the
`dotmage-spec` libsodium profile. However, until they are checked against frozen cross-client
test vectors, do not assume a blob written by this SDK can be decrypted by `dmage` (or vice
versa), and do not rely on it in production.

Points that must match exactly for interoperability, and that the vector suite must pin:

- The AEAD primitive: **`crypto_secretbox` (XSalsa20-Poly1305)** vs any XChaCha20 variant.
- Salt length (16), nonce length (24), key length (32).
- `memlimit` units: **bytes** (`memory_kib * 1024`), and `opslimit = iterations`,
  parallelism 1, `ALG_ARGON2ID13` (version 19).
- base64 flavour: **standard** (not URL-safe) for all `b64` fields.
- The blob envelope layout `version(1) ‖ nonce(24) ‖ ciphertext` and `BLOB_VERSION = 1`.
- Canonical JSON: sorted keys, `separators=(",", ":")`, `ensure_ascii=False`, UTF-8.
- Recovery code: 20 bytes → base32, `=`-stripped, uppercased/de-hyphenated before KDF.
- Invitation seal-key derivation, including the exact domain-separation label
  `b"dotmage/invite/seal/v1\x00"`.

The reconciliation step is `tests/test_crypto_vectors.py`: frozen
`(master_password, salt, ...) -> expected bytes` pairs that lock the format and guard against
regressions, tagged as the contract with `dmage`. Treat `suite.py` as the one place to change
if a mismatch is found. This warning is repeated in the docstring of `suite.py` itself.
