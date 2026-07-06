# API reference

Every public method of [`DotMage`](modules/client.md) and its asynchronous mirror
[`AsyncDotMage`](modules/async_client.md), mapped to the HTTP endpoint(s) it calls (from
`core/api/spec.py`) and the type it returns.

The two clients are identical in name, signature, and semantics. On `AsyncDotMage` every
network method is a coroutine (`await ...`), the constructors `init_vault` / `enroll` / `join`
/ `from_ci` are awaited classmethods, and resource cleanup is `await aclose()` instead of
`close()`. `lock()` and `is_unlocked` are synchronous on both. Signatures below are shown for
the sync client; prefix async equivalents with `await`.

### Legend

- **Unlock?** — "yes" means the method needs the account key in memory (an unlocked
  [session](modules/session.md)); it encrypts, decrypts, or seals locally. Calling it while
  locked raises [`LockedError`](modules/exceptions.md).
- **Role** — minimum server-enforced [role](security-model.md#roles-authorization-over-ciphertext)
  required. Team-only endpoints (marked *team*) return
  [`TeamModeRequiredError`](modules/exceptions.md) on a solo server.
- Endpoints are relative to the server base URL; the API prefix is `/api/v1` (except
  `/health`).

## Lifecycle

| Method (signature) | Does | HTTP endpoint(s) | Returns | Unlock? | Role |
|--------------------|------|------------------|---------|---------|------|
| `DotMage(server_url=None, *, store=None, settings=None, timeout=None, max_retries=None)` | Construct a client; resolves URL and credential store | — | `DotMage` | — | — |
| `init_vault(server_url, bootstrap_secret, master_password, *, with_recovery=True, device_name="sdk", store=None)` *(classmethod)* | Create a new vault on a fresh server; generate + wrap AK; register first device; ends unlocked | `POST /account/init` | `tuple[DotMage, str \| None]` (client, recovery code) | sets key | — (bootstrap) |
| `enroll(server_url, enroll_token, master_password, *, device_name="sdk", store=None)` *(classmethod)* | Register this machine as a new device, then unlock | `POST /auth/device`, `GET /account/keys` | `DotMage` | ends unlocked | — |
| `join(server_url, invitation_id, redeem_secret, master_password, *, device_name="sdk", with_recovery=True, store=None)` *(classmethod)* | Join a team from an invitation; open sealed AK; re-wrap under own password | `POST /invitations/redeem`, `POST /invitations/complete` | `tuple[DotMage, str \| None]` | sets key | *team* |
| `from_ci(server_url, ci_token, master_password, *, store=None)` *(classmethod)* | Build a client from a scoped CI device token and unlock | `GET /account/keys` | `DotMage` | ends unlocked | — |
| `unlock(master_password)` | Fetch wrapped AK and unwrap with master password | `GET /account/keys` | `None` | sets key | — |
| `unlock_with_recovery(recovery_code)` | Unwrap AK using the recovery code | `GET /account/keys` | `None` | sets key | — |
| `lock()` | Forget the in-memory account key | — | `None` | — | — |
| `change_master_password(old_password, new_password)` | Unlock with old password, re-wrap AK under new one | `GET /account/keys`, `PATCH /account/keys` | `None` | yes | — |
| `is_unlocked` *(property)* | Whether the account key is held in memory | — | `bool` | — | — |
| `health()` | Server health / feature discovery | `GET /health` | `Health` | no | — (unauth) |
| `whoami()` | Current user/device identity | `GET /whoami` | `WhoAmI` | no | viewer |
| `close()` / `aclose()` | Release HTTP client and lock the session | — | `None` | — | — |

## Apps & environments

| Method (signature) | Does | HTTP endpoint(s) | Returns | Unlock? | Role |
|--------------------|------|------------------|---------|---------|------|
| `list_apps()` | List apps | `GET /apps` | `list[App]` | no | viewer |
| `create_app(name)` | Create an app (names may contain `/`) | `POST /apps` | `App` | no | editor |
| `delete_app(name)` | Delete an app | `DELETE /apps/{name}` | `None` | no | owner |
| `list_envs(app)` | List environments of an app | `GET /apps/{app}/envs` | `list[Environment]` | no | viewer |
| `create_env(app, name, *, copy_from=None)` | Create an environment, optionally copying another | `POST /apps/{app}/envs` | `Environment` | no | editor |
| `delete_env(app, env)` | Delete an environment | `DELETE /apps/{app}/envs/{env}` | `None` | no | owner |

## Secrets

| Method (signature) | Does | HTTP endpoint(s) | Returns | Unlock? | Role |
|--------------------|------|------------------|---------|---------|------|
| `pull(app, env, rev="last", *, verify=True)` | Fetch a revision and decrypt to an env dict; optionally verify content hash | `GET /apps/{app}/envs/{env}/revisions/{rev}` | `dict[str, str]` | **yes** | viewer |
| `pull_text(app, env, rev="last")` | Like `pull`, serialised to `.env` text | `GET .../revisions/{rev}` | `str` | **yes** | viewer |
| `pull_to_file(app, env, path, rev="last")` | Like `pull_text`, written to a file | `GET .../revisions/{rev}` | `None` | **yes** | viewer |
| `push(app, env, data, *, base_rev=None)` | Encrypt and push a new revision; `base_rev` defaults to the current latest | `GET /apps/{app}/envs` (for latest rev), `POST .../revisions` | `RevisionMeta` | **yes** | editor |
| `push_from_file(app, env, path)` | Read a `.env` file and `push` it | `GET .../envs`, `POST .../revisions` | `RevisionMeta` | **yes** | editor |
| `set(app, env, updates)` | Merge `updates` into the latest revision and push | `GET .../revisions/last`, `GET .../envs`, `POST .../revisions` | `RevisionMeta` | **yes** | editor |

`push` raises [`RevisionConflictError`](modules/exceptions.md) (HTTP 409) if the remote moved
past `parent_rev` — pull, merge, and retry.

## Revisions

| Method (signature) | Does | HTTP endpoint(s) | Returns | Unlock? | Role |
|--------------------|------|------------------|---------|---------|------|
| `list_revisions(app, env)` | List revision metadata (no blobs) | `GET /apps/{app}/envs/{env}/revisions` | `list[RevisionMeta]` | no | viewer |
| `get_revision(app, env, rev="last")` | Fetch a raw revision (encrypted blob, undecrypted) | `GET .../revisions/{rev}` | `Revision` | no | viewer |
| `rollback(app, env, to_rev)` | Server-side copy of an old revision to a new one | `POST .../rollback` | `RollbackResult` | no | editor |
| `diff(app, env, a, b="last")` | Decrypt two revisions and compute a per-key diff locally | `GET .../revisions/{a}`, `GET .../revisions/{b}` | `Diff` | **yes** | viewer |
| `status(app, env, local)` | Classify a local env against the latest remote revision by content hash | `GET .../revisions` | `DriftStatus` | no | viewer |

## Devices

| Method (signature) | Does | HTTP endpoint(s) | Returns | Unlock? | Role |
|--------------------|------|------------------|---------|---------|------|
| `list_devices()` | List enrolled devices | `GET /devices` | `list[DeviceInfo]` | no | viewer |
| `revoke_device(device_id)` | Revoke a device | `DELETE /devices/{device_id}` | `None` | no | viewer |
| `gen_enroll_token(name="new-device", ttl="1h")` | Issue an enrollment token for a new device | `POST /devices/enroll-token` | `EnrollToken` | no | viewer |
| `gen_ci_token(app, env, ttl="30d")` | Issue a scoped CI device token for one app+env | `POST /devices/ci-token` | `DeviceCredentials` | no | viewer |

*Device routes require any authenticated device token; they are not role-gated in the backend.*

## Team

| Method (signature) | Does | HTTP endpoint(s) | Returns | Unlock? | Role |
|--------------------|------|------------------|---------|---------|------|
| `list_users()` | List team members and pending invitations | `GET /users` | `Team` | no | viewer *(team)* |
| `invite(name, role="editor", ttl="24h")` | Create an invitation, sealing the AK for the invitee | `POST /users/invite` | `InvitePayload` | **yes** | viewer *(team)* |
| `change_role(user_id, role)` | Change a member's role | `PATCH /users/{user_id}` | `None` | no | owner *(team)* |
| `remove_user(user_id)` | Remove a member (revokes their devices) | `DELETE /users/{user_id}` | `RemoveResult` | no | owner *(team)* |

`invite` returns an [`InvitePayload`](modules/models.md) containing the `redeem_secret` to
hand to the invitee out of band (see [crypto: invitation sealing](crypto.md#invitation-sealing)).
`RemoveResult.rotation_required` signals when you should `rotate` after off-boarding.

## Rotation

| Method (signature) | Does | HTTP endpoint(s) | Returns | Unlock? | Role |
|--------------------|------|------------------|---------|---------|------|
| `rotation_status()` | Current rotation state and stale revisions | `GET /account/rotate` | `RotationStatus` | no | viewer |
| `rotate(master_password, *, with_recovery=False, progress=None)` | Generate a new AK, re-encrypt every revision, cut over; resumable | `GET /account/keys`, `GET /account/rotate`, `POST /account/rotate/begin`, `GET .../revisions/{rev}` + `PUT .../revisions/{rev}/blob` (per stale), `POST /account/rotate/complete` | `str \| None` (new recovery code) | **yes** | owner |

`progress` is a `Callable[[done, total], None]` invoked as each stale blob is re-encrypted.

## Audit

| Method (signature) | Does | HTTP endpoint(s) | Returns | Unlock? | Role |
|--------------------|------|------------------|---------|---------|------|
| `audit(*, app=None, env=None, limit=100)` | Fetch audit-log events, optionally filtered | `GET /audit` | `list[AuditEvent]` | no | viewer |

## See also

- [`client`](modules/client.md) / [`async_client`](modules/async_client.md) — the method
  implementations.
- [`models`](modules/models.md) — every return type.
- [`exceptions`](modules/exceptions.md) — error mapping and the full hierarchy.
- [security model](security-model.md) — what "unlock" and "role" mean.
