# Module: `dotmage.exceptions`

Every error the SDK raises descends from `DotMageError`. Two families live here: **API errors**
that mirror the server's domain errors (mapped from the response body), and **client-side
errors** raised locally — most importantly when decryption fails because the master password is
wrong. This page lists the hierarchy and how server error codes map onto it.

The common classes are re-exported from the package root:

```python
from dotmage import (
    DotMageError, DotMageAPIError, DecryptionError, MasterPasswordError,
    RevisionConflictError, RotationError, TeamModeRequiredError,
)
```

## Hierarchy

```
DotMageError
├── DotMageAPIError                 (status_code, code, payload)
│   ├── AuthenticationError         (401)
│   │   ├── TokenExpiredError
│   │   ├── DeviceRevokedError
│   │   └── EnrollmentError
│   ├── BootstrapError              (403)
│   ├── AccountStateError
│   ├── ForbiddenError              (403)
│   ├── NotFoundError               (404)
│   ├── BadRequestError             (400)
│   ├── RevisionConflictError       (409; server_rev, parent_rev)
│   ├── RotationError
│   ├── TeamModeRequiredError       (404 on solo servers)
│   ├── TeamError
│   └── RateLimitError              (429)
└── CryptoError
    ├── DecryptionError
    │   └── MasterPasswordError
    ├── ContentIntegrityError
    └── InteropError
ConfigError (DotMageError)
└── LockedError
```

## API errors

`DotMageAPIError` carries `status_code`, `code` (the server-side error class name), and the raw
`payload`. The server serialises every domain error as
`{"error": {"code": "<ClassName>", "message": "..."}}` with a matching HTTP status (see
`server/src/core/auth/exceptions.py`).

- `AuthenticationError` — missing, invalid, or revoked credentials (401).
  - `TokenExpiredError` — the device token expired; the transport attempts a refresh.
  - `DeviceRevokedError` — the device or its enrollment token was revoked.
  - `EnrollmentError` — enrollment token missing/invalid/revoked/expired.
- `BootstrapError` — the bootstrap secret was rejected (403).
- `AccountStateError` — account already initialised, or not initialised.
- `ForbiddenError` — the caller's role or token scope forbids the action (403).
- `NotFoundError` — app, env, revision, device, or user not found (404).
- `BadRequestError` — malformed request, e.g. a bad revision selector (400).
- `RevisionConflictError` — push rejected because the remote is ahead (409). Adds
  `server_rev` and `parent_rev`, parsed best-effort from the message.
- `RotationError` — a key-rotation precondition failed (in progress / incomplete / not active
  / conflict).
- `TeamModeRequiredError` — a team-only endpoint was called on a solo server (404 with a team
  code).
- `TeamError` — team management error (bad invitation, user exists, last owner, ...).
- `RateLimitError` — too many requests (429).

## Client-side errors

- `CryptoError` — base for local cryptographic failures.
  - `DecryptionError` — authenticated decryption failed (wrong key, tampered ciphertext, or
    bad format). Raised by [`aead.decrypt`](crypto.md#aead-authenticated-encryption).
  - `MasterPasswordError` — the master password or recovery code could not unwrap the account
    key. Raised by `keys.unwrap_account_key*`.
  - `ContentIntegrityError` — a decrypted blob did not match its expected `content_hash`
    (from `pull(..., verify=True)`).
  - `InteropError` — a ciphertext/envelope used a version or format this SDK does not
    understand (see [crypto contract → interop](../crypto.md#interoperability-status)).
- `ConfigError` — the SDK was misconfigured (e.g. no server URL).
  - `LockedError` — an operation needed the account key but the [session](session.md) is
    locked. Call `unlock()` first.

## Error-code mapping

`error_from_response(status_code, payload) -> DotMageAPIError` builds the right subclass. It
looks up the server `error.code` in `_CODE_MAP`, then falls back to the HTTP status via
`_status_fallback`. FastAPI validation bodies (`{"detail": ...}`) are tolerated. Selected
mappings:

| Server code (`server/src/core/auth/exceptions.py`) | SDK class |
|-----------------------------------------------------|-----------|
| `TokenExpiredError` | `TokenExpiredError` |
| `DeviceRevokedError` | `DeviceRevokedError` |
| `InvalidEnrollmentTokenError`, `EnrollmentToken*Error` | `EnrollmentError` |
| `InvalidBootstrapError` | `BootstrapError` |
| `AccountExistsError`, `AccountNotFoundError` | `AccountStateError` |
| `AppNotFoundError`, `EnvNotFoundError`, `RevisionNotFoundError`, `UserNotFoundError`, `DeviceNotFoundError` | `NotFoundError` |
| `BadRevisionError` | `BadRequestError` |
| `RevisionConflictError` | `RevisionConflictError` |
| `RotationInProgressError`, `RotationConflictError`, `RotationNotActiveError`, `RotationIncompleteError` | `RotationError` |
| `NotAnOwnerError`, `RoleForbiddenError`, `DeviceScopeError` | `ForbiddenError` |
| `TeamModeRequiredError` | `TeamModeRequiredError` |
| `AppExistsError`, `EnvExistsError`, `UserExistsError`, `InvitationInvalidError`, `LastOwnerError` | `TeamError` |
| `RateLimitedError` | `RateLimitError` |

Status fallbacks: `400 → BadRequestError`, `401 → AuthenticationError`, `403 → ForbiddenError`,
`404 → NotFoundError`, `429 → RateLimitError`, else `DotMageAPIError`.

## Example

```python
from dotmage.exceptions import RevisionConflictError, MasterPasswordError, LockedError

try:
    dm.push("work/api", "prod", data)
except RevisionConflictError as exc:
    print("remote at", exc.server_rev, "you based on", exc.parent_rev)

try:
    dm.unlock("wrong password")
except MasterPasswordError:
    print("bad master password")

try:
    dm.pull("work/api", "prod")   # while locked
except LockedError:
    dm.unlock("correct horse battery staple")
```

## References

- [`http`](http.md) — where `error_from_response` is invoked.
- [`crypto`](crypto.md) — sources of `DecryptionError` / `MasterPasswordError` /
  `ContentIntegrityError` / `InteropError`.
- [`session`](session.md) — raises `LockedError`.
- [API reference](../api-reference.md) — which methods can raise what.
- Backend: `server/src/core/auth/exceptions.py` (the authoritative code + status contract).
