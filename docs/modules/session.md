# Module: `dotmage.session`

The `Session` holds the decrypted **account key (AK)** and its generation in memory while a
client is unlocked. The AK is never written to disk; it lives here for the lifetime of an
unlocked [`DotMage`](client.md) / [`AsyncDotMage`](async_client.md) and is used to encrypt and
decrypt config blobs via the [`blob`](crypto.md#blob-envelope) primitives.

`Session` is an internal collaborator of the clients — you rarely construct it directly — but
understanding it clarifies what "unlocked" means.

## Class `Session`

```python
class Session:
    def __init__(self) -> None: ...

    is_unlocked: bool          # property — True once a key is set
    account_key: bytes         # property — raises LockedError if locked
    key_gen: int               # property — raises LockedError if locked

    def set_key(self, account_key: bytes, key_gen: int) -> None: ...
    def clear(self) -> None: ...
    def encrypt(self, data: dict[str, str]) -> tuple[str, str]: ...   # (blob, content_hash)
    def decrypt(self, ciphertext: str) -> dict[str, str]: ...
```

- `set_key(account_key, key_gen)` stores the unlocked AK and the generation it corresponds to.
  The clients call this after `unlock`, `unlock_with_recovery`, `init_vault`, `join`, and at
  the end of `rotate`.
- `account_key` / `key_gen` raise [`LockedError`](exceptions.md) when accessed on a locked
  session (`"session is locked — call unlock() first"`).
- `encrypt(data)` delegates to [`blob.encrypt_blob`](crypto.md#blob-envelope), returning the
  base64 envelope and the plaintext `content_hash`.
- `decrypt(ciphertext)` delegates to [`blob.decrypt_blob`](crypto.md#blob-envelope).
- `clear()` forgets the key, locking the session (used by `lock()` and `close()`/`aclose()`).

## Example

The session is managed for you by the client:

```python
from dotmage import DotMage

dm = DotMage("https://secrets.example.com")
assert dm.is_unlocked is False          # -> Session.is_unlocked
dm.unlock("correct horse battery staple")
assert dm.is_unlocked is True           # AK now held in Session
dm.pull("work/api", "prod")             # uses Session.decrypt internally
dm.lock()                               # Session.clear()
assert dm.is_unlocked is False
```

## References

- [`crypto`](crypto.md) — `blob.encrypt_blob` / `blob.decrypt_blob` that the session wraps.
- [`client`](client.md) / [`async_client`](async_client.md) — own a `Session` and call
  `set_key` / `clear`.
- [`exceptions`](exceptions.md) — `LockedError`.
- [security model](../security-model.md) — why the AK is memory-only and what it protects.
- `key_gen` mirrors the backend `Account.current_key_gen` / `Revision.key_gen` in
  `server/src/models/base.py`.
