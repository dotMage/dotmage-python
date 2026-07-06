# dotMage Python SDK

`dotmage` is the Python SDK for **[dotMage](https://github.com/dotMage/server)** — a
self-hosted, end-to-end encrypted `.env` secret manager.

The dotMage server is a **zero-knowledge blob store**: it only ever holds opaque encrypted
blobs and wrapped keys. It never sees your master password, your plaintext secrets, or the
account key (AK). Every cryptographic operation happens locally, inside this SDK; the server
is a synchronising, versioning, access-controlling store for ciphertext.

The package exposes two equivalent facades:

```python
from dotmage import DotMage        # synchronous
from dotmage import AsyncDotMage   # asynchronous mirror
```

## Table of contents

| Page | What it covers |
|------|----------------|
| [Getting started](getting-started.md) | Install, configure via `DOTMAGE_*`, first vault, unlock, sync vs async |
| [Security model](security-model.md) | Threat model: what the server sees and cannot see; roles; recovery; backup |
| [Cryptographic contract](crypto.md) | Exact primitives, sizes, blob envelope, sealed-AK, **interoperability status** |
| [API reference](api-reference.md) | Every public `DotMage` / `AsyncDotMage` method mapped to HTTP endpoints |
| **Module pages** | |
| [`client`](modules/client.md) | The synchronous `DotMage` client |
| [`async_client`](modules/async_client.md) | The asynchronous `AsyncDotMage` client |
| [`session`](modules/session.md) | In-memory unlocked account-key state |
| [`crypto`](modules/crypto.md) | Key derivation, wrapping, blob envelope, invitation sealing |
| [`http`](modules/http.md) | httpx transport, retries, token refresh |
| [`credentials`](modules/credentials.md) | Credential stores (memory, file) |
| [`models`](modules/models.md) | Typed response models and SDK value objects |
| [`exceptions`](modules/exceptions.md) | Exception hierarchy and server error-code mapping |
| [`settings`](modules/settings.md) | Environment-driven configuration (`DOTMAGE_*`) |
| [`dotenv`](modules/dotenv.md) | Dependency-free `.env` parser/serialiser |

## Architecture

The SDK is built in layers. A public client method (say `push`) turns a plaintext dict into
ciphertext locally, describes the HTTP call declaratively, and hands it to the transport. The
transport authenticates and sends it; the server only ever stores/returns opaque data.

```
        Your code
           │
           ▼
┌─────────────────────────────┐         ┌────────────────────────────┐
│  Facade layer               │         │  Session (side)            │
│  DotMage / AsyncDotMage     │◄───────►│  holds unlocked AK + key_gen│
│  client.py / async_client.py│         │  session.py                │
└─────────────┬───────────────┘         └────────────┬───────────────┘
              │                                       │
              │ builds RequestSpec                    │ encrypt / decrypt
              ▼                                       ▼
┌─────────────────────────────┐         ┌────────────────────────────┐
│  Endpoint specs             │         │  Client-side crypto (side) │
│  core/api/spec.py           │         │  core/crypto/*             │
│  (pure, no I/O)             │         │  suite,kdf,aead,keys,      │
└─────────────┬───────────────┘         │  blob,invitation           │
              │                          └────────────────────────────┘
              ▼
┌─────────────────────────────┐
│  HTTP transport             │
│  core/http/client.py        │
│  + retry.py (tenacity)      │
│  Bearer auth, 401 refresh   │
└─────────────┬───────────────┘
              │  HTTPS  /api/v1/...
              ▼
┌─────────────────────────────┐
│  dotMage server             │
│  zero-knowledge blob store  │
└─────────────────────────────┘
```

- The **facade layer** ([`client`](modules/client.md), [`async_client`](modules/async_client.md))
  is the only surface most users touch. The two clients share every non-network component.
- **Endpoint specs** ([`core/api/spec.py`](modules/http.md#endpoint-specs)) describe each
  request as a pure `RequestSpec` value — no I/O — so both facades and tests reuse them.
- The **transport** ([`http`](modules/http.md)) owns the httpx client, injects the device
  token, refreshes once on `401`, retries transient failures, and maps error bodies to the
  [exception hierarchy](modules/exceptions.md).
- **Client-side crypto** ([`crypto`](modules/crypto.md)) and the **session**
  ([`session`](modules/session.md)) sit to the side: the session holds the decrypted AK in
  memory, and the crypto modules perform all encryption, decryption, and key wrapping. The
  network layer never touches keys or plaintext.

See the [security model](security-model.md) for what this buys you, and the
[cryptographic contract](crypto.md) for the exact wire format.
