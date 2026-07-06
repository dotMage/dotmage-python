# Module: `dotmage.core.credentials`

Credential stores hold the **persisted, non-secret-bearing** session state — the device token,
refresh token, device id, expiry, and server URL. They deliberately do **not** hold the master
password or the account key (that lives only in the in-memory [session](session.md)). Two
implementations ship: an in-memory store (the default) and a file-backed store.

The public symbols are re-exported from the package root:

```python
from dotmage import Credentials, CredentialStore, MemoryStore, FileStore
```

## `Credentials`

A dataclass of the tokens a client needs between requests:

```python
@dataclass
class Credentials:
    server_url: str | None = None
    device_token: str | None = None
    refresh_token: str | None = None
    device_id: str | None = None
    expires_at: str | None = None

    def to_dict(self) -> dict[str, str | None]: ...
    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Credentials: ...
```

`from_dict` ignores unknown keys, keeping stored files forward-compatible.

## `CredentialStore` (abstract base)

```python
class CredentialStore(ABC):
    @abstractmethod
    def load(self) -> Credentials: ...          # empty Credentials if none stored
    @abstractmethod
    def save(self, credentials: Credentials) -> None: ...
    def clear(self) -> None: ...                 # save(Credentials())
```

The [transport](http.md) reads the current credentials via `load()` before each request and
`save()`s rotated tokens after a refresh; the clients `save()` after enrollment, init, or join.
Implement this ABC to back credentials with a keyring, secrets manager, etc.

## `MemoryStore`

```python
MemoryStore(credentials: Credentials | None = None)
```

Holds credentials in process memory only — nothing is written to disk. This is the **default**
store when you construct a client without one; the client seeds it from `DOTMAGE_DEVICE_TOKEN`
/ `DOTMAGE_REFRESH_TOKEN` (see [settings](settings.md)).

## `FileStore`

```python
FileStore(path: str | os.PathLike[str] | None = None)
```

Persists credentials as JSON. Default path: `~/.config/dotmage/credentials.json`. The file is
created/truncated with mode `0600` (owner read/write only) so tokens are not world-readable,
and the parent directory is created as needed. Use it to keep a device enrolled across process
runs:

```python
from dotmage import DotMage, FileStore

with DotMage("https://secrets.example.com", store=FileStore()) as dm:
    dm.unlock("correct horse battery staple")   # tokens loaded from disk
```

## Example: a custom store

```python
from dotmage import Credentials, CredentialStore

class DictStore(CredentialStore):
    def __init__(self) -> None:
        self._data: dict[str, object] = {}
    def load(self) -> Credentials:
        return Credentials.from_dict(self._data)
    def save(self, credentials: Credentials) -> None:
        self._data = credentials.to_dict()
```

## References

- [`http`](http.md) — the transport that loads/saves credentials and rotates tokens on refresh.
- [`client`](client.md) / [`async_client`](async_client.md) — accept a `store=` argument.
- [`settings`](settings.md) — seeds the default `MemoryStore` from env tokens.
- [`session`](session.md) — the *account key* lives here instead, never in a credential store.
- Backend: token issuance in `server/src/api/v1/account/routes.py` (`POST /account/init`),
  `server/src/api/v1/auth/routes.py` (`POST /auth/device`, `POST /auth/refresh`),
  `server/src/api/v1/devices/routes.py` (`ci-token`, `enroll-token`); `Device.token_hash` /
  `refresh_hash` / `token_expires_at` in `server/src/models/base.py`.
