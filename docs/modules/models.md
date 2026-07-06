# Module: `dotmage.models` (with `enums` and `core.diffing`)

`models` defines the typed objects the SDK returns: pydantic models that parse server payloads
and a few value objects the SDK produces locally (invite payloads, diffs, drift status). All
response models use `extra="ignore"`, keeping them forward-compatible as the server evolves.
This page also covers the shared [`enums`](#enums) and the pure diff/drift helpers in
`core.diffing` that produce some of these models.

## Response models

Parsed from server JSON (`model_config = ConfigDict(populate_by_name=True, extra="ignore")`).

| Model | Notable fields | Returned by |
|-------|----------------|-------------|
| `Health` | `status, version, account_exists, features: list[str], server_name` | `health()` |
| `DeviceCredentials` | `device_token, refresh_token, device_id, expires_at` | `init_vault`/`enroll`/`join`/`gen_ci_token` internals |
| `EnrollToken` | `token, expires_at` | `gen_enroll_token()` |
| `AccountKeys` | `salt, argon_memory, argon_iterations, argon_parallelism, argon_version, nonce_ak, wrapped_ak, salt_rc?, nonce_rc?, wrapped_ak_rc?, key_gen` | `GET /account/keys` (unlock, rotate) |
| `Environment` | `id, name, latest_rev, protected, created_at, updated_at` | `list_envs`, `create_env` |
| `App` | `id, name, created_at, updated_at, environments: list[Environment]` | `list_apps`, `create_app` |
| `RevisionMeta` | `rev_number, content_hash?, created_at, device_id, rollback_of?` | `push`, `list_revisions` |
| `Revision` | `rev_number, blob, content_hash?, created_at, device_id, parent_rev?, rollback_of?, key_gen` | `get_revision`, `pull` internals |
| `RollbackResult` | `rev_number, copied_from` | `rollback` |
| `DeviceInfo` | `id, name, last_seen?, expires_at, revoked, created_at, allowed_app?, allowed_env?` | `list_devices` |
| `WhoAmI` | `user_id?, name, role, device_id, device_name` | `whoami` |
| `Team` | `users: list[TeamUser], invitations: list[TeamInvitationInfo]` | `list_users` |
| `TeamUser` | `id, name, role, status, key_gen, created_at` | inside `Team` |
| `TeamInvitationInfo` | `id, name, role, status, expires_at` | inside `Team` |
| `RedeemResponse` | `sealed_ak, nonce_inv, key_gen, name, role, argon_defaults: ArgonDefaults` | `join` internals |
| `ArgonDefaults` | `memory, iterations, parallelism, version` | inside `RedeemResponse` |
| `InviteResult` | `invitation_id, expires_at` | `invite` internals |
| `RemoveResult` | `id, name, devices_revoked, rotation_required` | `remove_user` |
| `RotationStatus` | `in_progress, current_key_gen, new_key_gen?, stale_count?, stale: list[StaleRevision], pending_nonce_ak?, pending_wrapped_ak?` | `rotation_status`, `rotate` |
| `StaleRevision` | `app, env, rev_number` | inside `RotationStatus` |
| `RotateBeginResult` | `new_key_gen, stale_count` | `rotate` internals |
| `AuditEvent` | `id, device_id?, user?, action, app_name?, env_name?, rev_number?, at` | `audit` |

### Token-field aliasing

`DeviceCredentials.expires_at` uses `AliasChoices("token_expires_at", "expires_at")` because
the field is named `token_expires_at` on init/auth/refresh responses but `expires_at` on
ci/enroll/complete responses. This is the one cross-endpoint naming quirk the models normalise.

## SDK value objects

Produced locally, not raw server payloads:

- `InvitePayload` — `invitation_id, redeem_secret, name, role, expires_at`. The shareable half
  of an invitation; hand `redeem_secret` to the invitee out of band. Returned by `invite`.
- `KeyChange` — `key, kind: ChangeKind, old?, new?`.
- `Diff` — `app, env, rev_a, rev_b, changes: list[KeyChange]`, with properties `added`,
  `removed`, `changed` and a `pretty()` renderer (unchanged keys omitted). Returned by `diff`.
- `DriftStatus` — `app, env, state: DriftState, local_hash?, remote_hash?, remote_rev`.
  Returned by `status`.

## Enums

From `dotmage.enums`:

| Enum | Members |
|------|---------|
| `MethodEnum` | `GET, POST, PUT, PATCH, DELETE` |
| `Role` | `OWNER, EDITOR, VIEWER` |
| `ServerFeature` | `ROTATION, TEAM` (advertised by `GET /health`) |
| `DriftState` | `SYNCED, LOCAL_AHEAD, REMOTE_AHEAD, DIVERGED, NO_REMOTE` |
| `ChangeKind` | `ADDED, REMOVED, CHANGED, UNCHANGED` |
| `AuditAction` | `account.init`, `push`, `pull`, `rollback`, `rotate.begin`, ... (mirrors `server/src/enums/audit.py`) |

## `core.diffing`

Pure functions that build the `Diff` / `DriftStatus` value objects (shared by both facades):

```python
compute_diff(app, env, rev_a, rev_b, data_a, data_b) -> Diff
compute_drift(app, env, local, remote_hash, remote_rev) -> DriftStatus
```

`compute_drift` hashes the local dict with [`blob.content_hash`](crypto.md#blob-envelope) and
compares it to the remote's stored hash — so `status` needs no decryption (no unlock). With
`remote_rev == 0` the state is `NO_REMOTE`; equal hashes give `SYNCED`; otherwise `DIVERGED`.

## Example

```python
diff = dm.diff("work/api", "prod", 3, "last")
print(diff.pretty())
for change in diff.changed:
    print(change.key, change.old, "->", change.new)

status = dm.status("work/api", "prod", open(".env").read())
print(status.state)          # DriftState.SYNCED / DIVERGED / NO_REMOTE
```

## References

- [API reference](../api-reference.md) — which method returns each model.
- [`crypto`](crypto.md) — `content_hash` / `blob` that drift and diff rely on.
- [`client`](client.md) / [`async_client`](async_client.md) — validate responses into these
  models.
- Backend: `server/src/models/base.py` (`Account`, `App`, `Environment`, `Revision`, `Device`,
  `User`, `Invitation`, `AuditLog`) and the per-endpoint response shapes in
  `server/src/api/v1/*/views.py`.
