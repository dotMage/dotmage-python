# Module: `dotmage.core.http` (and `core.api.spec`)

The transport layer is the SDK's only network component: authenticated, retrying request
helpers over [httpx](https://www.python-httpx.org/). A `Transport` (sync) or `AsyncTransport`
(async) owns an httpx client, a [credential store](credentials.md), and a
[tenacity](https://tenacity.readthedocs.io/) retry controller. It injects the device token,
transparently refreshes an expired token once on `401`, retries transient failures, and maps
error responses to the [exception hierarchy](exceptions.md). Requests themselves are described
declaratively by `core.api.spec`.

Most users never touch this layer directly — [`DotMage`](client.md) /
[`AsyncDotMage`](async_client.md) build and drive it — but it defines the SDK's networking
behaviour.

## `Transport` / `AsyncTransport`

```python
Transport(
    server_url: str,
    store: CredentialStore | None = None,
    *,
    timeout: float = 10.0,
    max_attempts: int = 5,
    retry_initial: float = 0.5,
    retry_max: float = 10.0,
)
```

Key members (identical on both, `async` where noted):

- `server_url` — normalised (trailing slash stripped). An empty URL raises
  [`ConfigError`](exceptions.md).
- `credentials` *(property)* — loads current [`Credentials`](credentials.md) from the store.
- `request(method, path, *, json=None, params=None, auth=True, headers=None) -> dict` — send a
  request, refreshing once on `401` (when `auth` and a refresh token exists), and return the
  decoded JSON body. *(async on `AsyncTransport`.)*
- `refresh()` — rotate the device/refresh tokens via `POST /api/v1/auth/refresh` using the
  stored refresh token; persists the new tokens. *(async on `AsyncTransport`.)*
- `close()` / `aclose()` — release the underlying httpx client.

Both are context managers (`with Transport(...)` / `async with AsyncTransport(...)`).

### Behaviour

- **Auth injection.** When `auth=True`, the stored `device_token` is sent as
  `Authorization: Bearer <token>`; `Content-Type: application/json` is always set. Per-request
  `headers` override defaults (e.g. the enrollment token in `POST /auth/device`).
- **One-shot refresh.** A `401` on an authenticated request triggers a single `refresh()` then
  one retry. If refresh is impossible (no refresh token) the `401` propagates as an
  [`AuthenticationError`](exceptions.md).
- **Error mapping.** Any response `>= 400` is turned into the right
  [`DotMageAPIError`](exceptions.md) subclass by `error_from_response` (see
  [exceptions](exceptions.md)). Successful bodies are decoded to a `dict` (a non-dict JSON body
  becomes `{"data": ...}`).

## `core.http.retry`

The retry policy, built on tenacity.

```python
RETRYABLE_STATUS_CODES = frozenset({408, 429, 500, 502, 503, 504})

is_retryable_status(response) -> bool
build_sync_retrying(max_attempts, *, initial=0.5, maximum=10.0) -> tenacity.Retrying
build_async_retrying(max_attempts, *, initial=0.5, maximum=10.0) -> tenacity.AsyncRetrying
```

- Retries on transient httpx exceptions (`ConnectError`, `ConnectTimeout`, `ReadTimeout`,
  `WriteTimeout`, `PoolTimeout`, `RemoteProtocolError`) **and** on retryable status codes,
  which are surfaced internally as a private `_RetryableStatus` so one predicate covers both.
- Backoff is exponential with jitter (`wait_exponential_jitter`), unless `initial <= 0` (then
  no wait — used in tests). `stop_after_attempt(max_attempts)`, `reraise=True`.

## Endpoint specs (`core.api.spec`)

Each endpoint is a pure function returning a frozen `RequestSpec`; no I/O happens here, so
both facades and the test suite reuse them.

```python
@dataclass(frozen=True)
class RequestSpec:
    method: MethodEnum
    path: str
    json: dict | None = None
    params: dict | None = None
    auth: bool = True
    headers: dict[str, str] | None = None
```

Representative spec functions (prefix `/api/v1` unless noted):

| Function | Method + path |
|----------|---------------|
| `health()` | `GET /health` (auth=False) |
| `account_init(body)` | `POST /account/init` (auth=False) |
| `get_keys()` / `patch_keys(body)` | `GET` / `PATCH /account/keys` |
| `auth_device(enroll_token, device_name)` | `POST /auth/device` (enroll token in header) |
| `list_apps()` / `create_app(name)` / `delete_app(name)` | `GET` / `POST /apps`, `DELETE /apps/{name}` |
| `list_envs(app)` / `create_env(app, name, copy_from)` / `delete_env(app, env)` | `.../apps/{app}/envs...` |
| `push_revision(...)` / `get_revision(...)` / `list_revisions(...)` / `rollback(...)` | `.../revisions...`, `.../rollback` |
| `list_devices()` / `revoke_device(id)` / `enroll_token(...)` / `ci_token(...)` | `.../devices...` |
| `whoami()` / `list_users()` / `invite(body)` / `redeem(...)` / `complete(body)` / `change_role(...)` / `remove_user(id)` | team endpoints |
| `rotate_begin(body)` / `rotate_status()` / `rotate_complete()` / `put_blob(...)` | `.../account/rotate...`, `.../revisions/{rev}/blob` |
| `audit(app, env, limit)` | `GET /audit` |

App names may contain slashes (folder-style) and are placed into the path verbatim to match
the server's `{name:path}` parameter; environment names are URL-encoded as plain segments.

## Example

Driving the transport directly (normally the client does this):

```python
from dotmage.core.http.client import Transport
from dotmage.core.api import spec

t = Transport("https://secrets.example.com")
health = t.request(spec.health().method, spec.health().path, auth=False)
print(health["status"])
t.close()
```

## References

- [`credentials`](credentials.md) — the store the transport reads/writes tokens through.
- [`exceptions`](exceptions.md) — `error_from_response` and the API error classes.
- [`enums`](models.md) — `MethodEnum`.
- [`client`](client.md) / [`async_client`](async_client.md) — consumers of the transport.
- [`settings`](settings.md) — `TIMEOUT`, `MAX_RETRIES` defaults.
- Backend: every route under `server/src/api/v1/*/routes.py`; refresh at
  `POST /api/v1/auth/refresh` (`server/src/api/v1/auth/routes.py`); error contract in
  `server/src/core/auth/exceptions.py`.
