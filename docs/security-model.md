# Security model

dotMage is designed so that a **compromised server, database, or backup reveals no secrets**.
This page describes the threat model: what the server can see, what it provably cannot see,
the role of the master password and recovery code, how team roles work, and why the recovery
code must be backed up.

See also: [cryptographic contract](crypto.md) for exact primitives · [`crypto`](modules/crypto.md)
module page · [`session`](modules/session.md).

## The zero-knowledge principle

The server is a **zero-knowledge blob store**. All cryptography runs inside this SDK (or the
reference `dmage` CLI). The server stores, versions, and authorises access to ciphertext, but
holds no key capable of reading it.

Every secret payload is encrypted under an **account key (AK)** — a random 32-byte symmetric
key shared across the whole account/team. The AK itself is stored only in *wrapped* form:
encrypted under a **key-encryption key (KEK)** that is derived from your master password with
Argon2id. The KEK and AK exist only in client memory ([`session`](modules/session.md)); they
are never transmitted.

## What the server sees

The server persists (and can therefore expose if breached):

| Data | Where (backend `server/src/models/base.py`) | Notes |
|------|---------------------------------------------|-------|
| Ciphertext blobs | `Revision.blob` | base64 envelope `version‖nonce‖ciphertext`; opaque |
| Content hash | `Revision.content_hash` | SHA-256 of *plaintext*; stored for client drift/diff, **not validated** server-side |
| Key generation | `Revision.key_gen`, `Account.current_key_gen` | which AK generation a blob is under |
| Wrapped account key | `Account.nonce_ak`, `Account.wrapped_ak` (and per-`User` in team mode) | AK encrypted under the master-password KEK |
| Recovery wrap | `Account.salt_rc`, `Account.nonce_rc`, `Account.wrapped_ak_rc` | AK encrypted under the recovery-code KEK |
| KDF parameters | `Account.salt`, `argon_memory`, `argon_iterations`, `argon_parallelism`, `argon_version` | needed by the client to re-derive the KEK; public by design |
| Sealed AK (invitations) | `Invitation.sealed_ak`, `Invitation.nonce_inv`, `Invitation.redeem_hash` | AK sealed under a key derived from the redeem secret |
| Metadata | app/env names, revision numbers, timestamps, device names, roles, audit log | plaintext — used for authorisation and history |
| Token hashes | `Device.token_hash`, `Device.refresh_hash` | hashes of device/refresh tokens |

**Metadata is not encrypted.** App names, environment names, revision history, device names,
who did what and when (the audit log) are all visible to the server. Do not put secret values
into names.

## What the server cannot see

Because the KEK is derived client-side and the AK is only ever uploaded wrapped:

- **The master password** — never leaves the client, in any form.
- **The recovery code** — never leaves the client; only the *wrap it produces* is stored.
- **The account key (AK)** — the server holds only ciphertext wraps of it. Unwrapping requires
  the master password or recovery code, neither of which the server has.
- **Plaintext secrets** — the server sees only AEAD ciphertext. It cannot decrypt a `blob`.
- **The invitation redeem secret** — the server stores only `sha256(redeem_secret)`
  (`redeem_hash`) to gate delivery; the AK is sealed under a *domain-separated* key derived
  from the same secret, so `redeem_hash` alone cannot open `sealed_ak`. See
  [crypto: invitation sealing](crypto.md#invitation-sealing).

Even the `content_hash` the server stores is of the plaintext but the server never has the
plaintext to recompute it — it is a convenience for clients to detect drift, and integrity is
actually enforced by the AEAD tag on decryption, not by the hash.

## Master password and recovery code

- The **master password** is the root of trust. It derives (via Argon2id + salt) the KEK that
  wraps the AK. Changing it (`change_master_password`) re-wraps the same AK under a new KEK —
  the AK and therefore all existing ciphertext are unaffected.
- The **recovery code** is an independent 160-bit random secret generated at vault creation
  (and optionally at rotation). It wraps the *same* AK under a second KEK, stored in the
  `*_rc` fields. It is your only fallback if the master password is lost.

Both are used purely to unwrap the AK; both are verified implicitly by whether AEAD decryption
of the wrap succeeds. A wrong password/code surfaces as
[`MasterPasswordError`](modules/exceptions.md).

## Roles: authorisation over ciphertext

Team roles (`owner`, `editor`, `viewer`) are an **authorisation layer enforced by the server**,
*not* a cryptographic boundary. Everyone who can unlock holds the same account key and can
decrypt any blob they are allowed to fetch. Roles decide *which requests the server accepts*:

| Role | Can do (server-enforced) |
|------|--------------------------|
| `viewer` | Read: list apps/envs, list/get revisions, pull, whoami, audit |
| `editor` | Everything a viewer can, plus create apps/envs, push revisions, rollback |
| `owner` | Everything an editor can, plus delete apps/envs, manage users (invite/role/remove), and run key rotation |

Enforcement lives in the backend route dependencies (`require_editor`, `require_owner` in
`server/src/api/dependencies/auth.py`, wired in each `server/src/api/v1/*/routes.py`).
Because the AK is shared, **revoking a user does not retroactively protect past ciphertext
they already decrypted** — after off-boarding someone, rotate the key (see below). The server
signals this with `RemoveResult.rotation_required`.

The [API reference](api-reference.md) marks the required role and whether an unlocked session
(AK in memory) is needed for each method.

## Key rotation

Rotation replaces the AK with a fresh one and re-encrypts every stored revision under it, then
cuts over `current_key_gen`. Use it after removing a team member or if you suspect the old AK
was exposed. Rotation is owner-only, requires an unlocked session (the old AK is needed to
read existing blobs), and is resumable. See `rotate` in the [API reference](api-reference.md)
and [`client`](modules/client.md).

## Backup and irrecoverability

This is the most important operational consequence of zero-knowledge design:

> **If every copy of the master password *and* the recovery code is lost, the account key
> cannot be recovered, and every stored secret is permanently unreadable.** No one — including
> the server operator — can decrypt your data. There is no reset.

Therefore:

- Keep `init_vault`'s recovery code offline and safe. It is shown exactly once.
- Treat `bootstrap_secret`, device tokens, and CI tokens as credentials.
- When you rotate with `with_recovery=True`, the previous recovery code no longer unwraps the
  new AK — store the newly returned one.

## Backend field references

- Wrapped keys and KDF parameters: `Account` (`salt`, `argon_memory`, `argon_iterations`,
  `argon_parallelism`, `argon_version`, `nonce_ak`, `wrapped_ak`, `salt_rc`, `nonce_rc`,
  `wrapped_ak_rc`) and per-member `User` (same fields) in `server/src/models/base.py`.
- Ciphertext and generation: `Revision.blob`, `Revision.content_hash`, `Revision.key_gen`;
  `Account.current_key_gen` and the `rot_*` pending-wrap fields in `server/src/models/base.py`.
- Invitations: `Invitation.sealed_ak`, `Invitation.nonce_inv`, `Invitation.redeem_hash`,
  `Invitation.key_gen` in `server/src/models/base.py`.
- Role enforcement: `require_editor` / `require_owner` in `server/src/api/dependencies/auth.py`
  (used in `server/src/api/v1/apps/routes.py`, `.../revisions/routes.py`,
  `.../rotation/routes.py`, `.../users/routes.py`).
- Domain errors: `server/src/core/auth/exceptions.py` (e.g. `NotAnOwnerError`,
  `RoleForbiddenError`, `TeamModeRequiredError`).
