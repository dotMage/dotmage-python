# Module: `dotmage.async_client`

`AsyncDotMage` is the asynchronous mirror of [`DotMage`](client.md), built on
[`AsyncTransport`](http.md). Cryptography, endpoint specs, [session](session.md) state, and
diff/drift logic are shared with the sync client; only the network calls are awaited.

Import it from the package root:

```python
from dotmage import AsyncDotMage
```

## Relationship to the sync client

Method names, parameters, and return types are identical to [`DotMage`](client.md). The
differences are purely about the async runtime:

- Every method that performs network I/O is a coroutine — `await` it.
- The constructors `init_vault`, `enroll`, `join`, `from_ci` are awaited classmethods.
- Resource cleanup is `await aclose()` (and `async with AsyncDotMage(...) as dm:`), not
  `close()`.
- `lock()` and the `is_unlocked` property are synchronous (they only touch in-memory state).
- The `rotate(..., progress=...)` callback is an ordinary synchronous callable.

For the complete method-to-endpoint mapping, return types, and unlock/role requirements, see
the [API reference](../api-reference.md) — it applies to both clients.

## Construction

```python
AsyncDotMage(
    server_url: str | None = None,
    *,
    store: CredentialStore | None = None,
    settings: Settings | None = None,
    timeout: float | None = None,
    max_retries: int | None = None,
)
```

The constructor itself is synchronous (no I/O happens until a method is awaited). URL and
store resolution behaves exactly as in [`DotMage`](client.md#construction).

## Examples

Unlock and pull inside an event loop:

```python
import asyncio
from dotmage import AsyncDotMage

async def main() -> None:
    async with AsyncDotMage("https://secrets.example.com") as dm:
        await dm.unlock("correct horse battery staple")
        secrets = await dm.pull("work/api", "prod")
        print(secrets)

asyncio.run(main())
```

Create a vault (awaited classmethod):

```python
dm, recovery_code = await AsyncDotMage.init_vault(
    "https://secrets.example.com",
    bootstrap_secret="XXXXXXXXXXXX",
    master_password="correct horse battery staple",
)
await dm.create_app("work/api")
await dm.create_env("work/api", "prod")
await dm.push("work/api", "prod", {"DATABASE_URL": "postgres://..."})
await dm.aclose()
```

Fan out reads concurrently:

```python
import asyncio

async with AsyncDotMage("https://secrets.example.com") as dm:
    await dm.unlock("correct horse battery staple")
    prod, staging = await asyncio.gather(
        dm.pull("work/api", "prod"),
        dm.pull("work/api", "staging"),
    )
```

## References

- Sync equivalent (fuller narrative): [`client`](client.md).
- [API reference](../api-reference.md) — shared by both clients.
- [http](http.md) (`AsyncTransport`), [session](session.md), [crypto](crypto.md),
  [models](models.md), [exceptions](exceptions.md), [credentials](credentials.md),
  [settings](settings.md), [dotenv](dotenv.md).
- [security model](../security-model.md).
- Backend routes: `server/src/api/v1/*/routes.py` (same endpoints as the sync client).
