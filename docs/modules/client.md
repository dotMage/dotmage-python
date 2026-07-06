# Module: `dotmage.client`

The synchronous `DotMage` client is the SDK's primary entry point. It stitches together the
[HTTP transport](http.md), the [endpoint specs](http.md#endpoint-specs), client-side
[crypto](crypto.md), and an in-memory [session](session.md) into an ergonomic API where every
method that touches secrets encrypts or decrypts locally and the server sees only ciphertext.

Import it from the package root:

```python
from dotmage import DotMage
```

Full per-method mapping to HTTP endpoints, return types, unlock and role requirements lives in
the [API reference](../api-reference.md). This page summarises the class and shows idiomatic
usage.

## Construction

```python
DotMage(
    server_url: str | None = None,
    *,
    store: CredentialStore | None = None,
    settings: Settings | None = None,
    timeout: float | None = None,
    max_retries: int | None = None,
)
```

- `server_url` falls back to `DOTMAGE_SERVER_URL` (from [`settings`](settings.md)); if neither
  is set and the store holds no URL, [`ConfigError`](exceptions.md) is raised.
- `store` defaults to a [`MemoryStore`](credentials.md) seeded from `DOTMAGE_DEVICE_TOKEN` /
  `DOTMAGE_REFRESH_TOKEN`. Pass a [`FileStore`](credentials.md) to persist tokens.
- `timeout` / `max_retries` override the `TIMEOUT` / `MAX_RETRIES` settings for the
  [transport](http.md).

`DotMage` is a context manager: `with DotMage(...) as dm:` calls `close()` on exit, which
releases the HTTP connection and locks the session.

## Public surface

Constructors / lifecycle: `init_vault` *(classmethod)*, `enroll` *(classmethod)*,
`join` *(classmethod)*, `from_ci` *(classmethod)*, `unlock`, `unlock_with_recovery`, `lock`,
`change_master_password`, `is_unlocked` *(property)*, `close`, `health`, `whoami`.

Apps/envs: `list_apps`, `create_app`, `delete_app`, `list_envs`, `create_env`, `delete_env`.

Secrets: `pull`, `pull_text`, `pull_to_file`, `push`, `push_from_file`, `set`.

Revisions: `list_revisions`, `get_revision`, `rollback`, `diff`, `status`.

Devices: `list_devices`, `revoke_device`, `gen_enroll_token`, `gen_ci_token`.

Team: `list_users`, `invite`, `change_role`, `remove_user`.

Rotation: `rotation_status`, `rotate`.

Audit: `audit`.

## Examples

Create a vault, then push and pull:

```python
from dotmage import DotMage

dm, recovery_code = DotMage.init_vault(
    "https://secrets.example.com",
    bootstrap_secret="XXXXXXXXXXXX",
    master_password="correct horse battery staple",
)
dm.create_app("work/api")
dm.create_env("work/api", "prod")
dm.push("work/api", "prod", {"DATABASE_URL": "postgres://..."})
print(dm.pull("work/api", "prod"))
dm.close()
```

Unlock an existing device (persisted tokens) and safely update:

```python
from dotmage import DotMage, FileStore

with DotMage("https://secrets.example.com", store=FileStore()) as dm:
    dm.unlock("correct horse battery staple")
    dm.set("work/api", "prod", {"FEATURE_FLAG": "on"})   # merge + push
```

Handle a concurrent-write conflict:

```python
from dotmage.exceptions import RevisionConflictError

try:
    dm.push("work/api", "prod", new_env)
except RevisionConflictError as exc:
    remote = dm.pull("work/api", "prod")     # rev exc.server_rev
    remote.update(new_env)
    dm.push("work/api", "prod", remote)
```

Rotate the account key after off-boarding, with progress:

```python
def on_progress(done: int, total: int) -> None:
    print(f"re-encrypted {done}/{total}")

new_recovery = dm.rotate("correct horse battery staple",
                         with_recovery=True, progress=on_progress)
```

## How methods map to the layers

- Secret methods use the [session](session.md) to `encrypt`/`decrypt` via the
  [`blob`](crypto.md#blob-envelope) envelope before/after the network call.
- Every request is described by a pure `RequestSpec` from `core/api/spec.py` and executed by
  the [`Transport`](http.md); responses are validated into [models](models.md).
- `invite` seals the account key with [`invitation`](crypto.md#invitation-sealing); `rotate`
  and `diff` decrypt existing blobs; `status` compares content hashes without unlocking.

## References

- Async equivalent: [`async_client`](async_client.md).
- [API reference](../api-reference.md) — endpoint, return type, unlock and role per method.
- [session](session.md), [crypto](crypto.md), [http](http.md), [credentials](credentials.md),
  [models](models.md), [exceptions](exceptions.md), [settings](settings.md),
  [dotenv](dotenv.md).
- [security model](../security-model.md) — trust boundaries and roles.
- Backend: routes under `server/src/api/v1/*/routes.py` (e.g. `account/routes.py` →
  `POST /account/init`, `GET`/`PATCH /account/keys`; `revisions/routes.py` → push/pull/rollback;
  `users/routes.py` → invite/redeem/complete/role/remove; `rotation/routes.py` → rotate).
