# Module: `dotmage.settings`

Runtime configuration for the SDK, read from the environment with the prefix `DOTMAGE_` via
`pydantic-settings`. Secrets are held as `SecretStr`, and a cached accessor `get_settings()`
returns a single shared instance. Both are re-exported from the package root.

```python
from dotmage import Settings, get_settings
```

## `Settings`

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DOTMAGE_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    SERVER_URL: str | None = None
    DEVICE_TOKEN: SecretStr | None = None
    REFRESH_TOKEN: SecretStr | None = None
    MASTER_PASSWORD: SecretStr | None = None

    TIMEOUT: float = 10.0
    MAX_RETRIES: int = 5
    LOG_LEVEL: str = "INFO"
```

| Field | Env var | Default | Used for |
|-------|---------|---------|----------|
| `SERVER_URL` | `DOTMAGE_SERVER_URL` | `None` | fallback base URL when a client is built without `server_url` |
| `DEVICE_TOKEN` | `DOTMAGE_DEVICE_TOKEN` | `None` | seeds the default [`MemoryStore`](credentials.md) |
| `REFRESH_TOKEN` | `DOTMAGE_REFRESH_TOKEN` | `None` | seeds the default `MemoryStore` |
| `MASTER_PASSWORD` | `DOTMAGE_MASTER_PASSWORD` | `None` | convenience for your own code to read; **not** auto-used to unlock |
| `TIMEOUT` | `DOTMAGE_TIMEOUT` | `10.0` | per-request httpx timeout in seconds |
| `MAX_RETRIES` | `DOTMAGE_MAX_RETRIES` | `5` | max transport attempts |
| `LOG_LEVEL` | `DOTMAGE_LOG_LEVEL` | `"INFO"` | loguru level |

Secret fields are `SecretStr`; read the underlying value with `.get_secret_value()`. A local
`.env` file (UTF-8, case-insensitive keys) is loaded automatically; unknown keys are ignored.

## `get_settings()`

```python
@lru_cache
def get_settings() -> Settings: ...
```

Returns a cached `Settings`. A client constructed without an explicit `settings=` calls this,
so the environment is read once per process. Because it is memoised, changing environment
variables at runtime will not be reflected until the cache is cleared
(`get_settings.cache_clear()`).

## How the clients use settings

At construction, [`DotMage`](client.md) / [`AsyncDotMage`](async_client.md):

1. Use `settings` (or `get_settings()`), then resolve the server URL from the `server_url`
   argument → `SERVER_URL` → the store's saved URL; if still empty, raise
   [`ConfigError`](exceptions.md).
2. If no `store` was passed, create a [`MemoryStore`](credentials.md) seeded with
   `DEVICE_TOKEN` / `REFRESH_TOKEN` (via `.get_secret_value()`).
3. Build the [transport](http.md) using `timeout` / `max_retries` arguments, falling back to
   `TIMEOUT` / `MAX_RETRIES`.

## Example

```bash
export DOTMAGE_SERVER_URL="https://secrets.example.com"
export DOTMAGE_DEVICE_TOKEN="dmage_dtok_..."
export DOTMAGE_MASTER_PASSWORD="correct horse battery staple"
```

```python
import os
from dotmage import DotMage, get_settings

dm = DotMage()                                   # URL + token from the environment
dm.unlock(get_settings().MASTER_PASSWORD.get_secret_value())
```

## References

- [`credentials`](credentials.md) — the store seeded from `DEVICE_TOKEN` / `REFRESH_TOKEN`.
- [`http`](http.md) — consumes `TIMEOUT` / `MAX_RETRIES`.
- [`client`](client.md) / [`async_client`](async_client.md) — resolution order at construction.
- [getting started](../getting-started.md#configuration-via-environment) — the env table.
