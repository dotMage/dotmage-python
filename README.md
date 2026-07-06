# dotmage

Python SDK for **[dotMage](https://github.com/dotMage/server)** — a self-hosted,
end-to-end encrypted `.env` secret manager.

The dotMage server is a **zero-knowledge blob store**: it only ever holds opaque encrypted
blobs and wrapped keys, and never sees your master password, plaintext secrets, or the
account key. This SDK therefore does two things:

1. **Transport** — a typed client over the dotMage REST API (`/api/v1`).
2. **Client-side cryptography** — key derivation, key wrapping/unwrapping, blob
   encryption/decryption, sealed-key team invitations, and key rotation — everything the
   reference `dmage` CLI does, so secrets are encrypted and decrypted locally.

> Status: **alpha**, under active development. The cryptographic wire format aims for
> byte-compatibility with the reference `dmage` client; see [`docs/crypto.md`](docs/crypto.md)
> and the interop notes before relying on it in production.

## Install

```bash
pip install dotmage
```

## Quickstart

```python
from dotmage import DotMage

# Create a vault on a fresh server (first device).
dm, recovery_code = DotMage.init_vault(
    "https://secrets.example.com",
    bootstrap_secret="XXXXXXXXXXXX",
    master_password="correct horse battery staple",
)
print("Store this recovery code somewhere safe (shown once):", recovery_code)

dm.create_app("work/api")
dm.create_env("work/api", "prod")
dm.push("work/api", "prod", {"DATABASE_URL": "postgres://...", "STRIPE_KEY": "sk_live_..."})

secrets = dm.pull("work/api", "prod")   # -> dict[str, str], decrypted locally
```

Async mirror:

```python
import asyncio
from dotmage import AsyncDotMage

async def main() -> None:
    async with AsyncDotMage("https://secrets.example.com") as dm:
        await dm.unlock("correct horse battery staple")
        print(await dm.pull("work/api", "prod"))

asyncio.run(main())
```

## Configuration

The SDK reads configuration from environment variables (prefix `DOTMAGE_`) via
`pydantic-settings`:

| Variable | Description |
|----------|-------------|
| `DOTMAGE_SERVER_URL` | Base URL of the dotMage server |
| `DOTMAGE_DEVICE_TOKEN` | Device token (`dmage_dtok_...`) |
| `DOTMAGE_REFRESH_TOKEN` | Refresh token (`dmage_rtok_...`) |
| `DOTMAGE_MASTER_PASSWORD` | Master password (used to unlock; keep it in a secret store) |

## Documentation

- [`docs/getting-started.md`](docs/getting-started.md)
- [`docs/security-model.md`](docs/security-model.md) — what the server can and cannot see
- [`docs/crypto.md`](docs/crypto.md) — exact cryptographic contract
- [`docs/api-reference.md`](docs/api-reference.md) — every method mapped to the HTTP API
- Per-module docs under [`docs/modules/`](docs/modules/)
- Runnable examples under [`examples/`](examples/)

## Development

```bash
poetry install
./scripts/linters.sh   # ruff + mypy
./scripts/tests.sh     # pytest with a 95% coverage gate
```

## Releasing

CI runs `check-version → lint → test → build` on every push to `main` and on pull requests.
Publishing to PyPI happens only on a version tag, once
[PyPI trusted publishing](https://docs.pypi.org/trusted-publishers/) is configured for this
repository (a GitHub environment named `pypi`):

```bash
# bump the version in pyproject.toml and update CHANGELOG.md, then:
git tag v0.1.0
git push origin v0.1.0
```

## License

MIT — see [LICENSE](LICENSE).
