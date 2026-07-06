# Module: `dotmage.dotenv`

A small, dependency-free `.env` parser and serialiser. The clients use it so `push` can accept
raw `.env` text (not just a dict) and `pull_text` / `pull_to_file` can emit `.env` files. It
supports the common subset of the format and produces deterministic output.

## Functions

```python
parse(text: str) -> dict[str, str]
serialize(data: dict[str, str]) -> str
```

### `parse`

Turns `.env` text into a dict. It handles:

- `KEY=VALUE` lines and `export KEY=VALUE`.
- `#` comment lines and blank lines (skipped).
- Single-quoted values (kept verbatim) and double-quoted values, where double quotes honour the
  escapes `\n`, `\t`, `\r`, `\\`, and `\"`.
- Lines without `=`, or with an empty key, are skipped.

Values are taken after the first `=`; surrounding whitespace on key and value is stripped
before quote handling.

### `serialize`

Turns a dict into `.env` text: **keys are sorted** for deterministic output, and each value is
quoted only when necessary. A value is double-quoted (with `\\`, `"`, newline, `\r`, `\t`
escaped) when it is empty or contains any of space, tab, newline, carriage return, `"`, `'`,
`#`, or `=`. The result ends with a trailing newline (empty input yields `""`).

## Example

```python
from dotmage import dotenv

env = dotenv.parse(
    """
    # database
    export DATABASE_URL="postgres://user:pass@host/db"
    API_KEY='sk_live_123'
    EMPTY=
    """
)
# {'DATABASE_URL': 'postgres://user:pass@host/db', 'API_KEY': 'sk_live_123', 'EMPTY': ''}

text = dotenv.serialize(env)
# API_KEY=sk_live_123
# DATABASE_URL="postgres://user:pass@host/db"
# EMPTY=""
```

Used implicitly by the clients:

```python
dm.push("work/api", "prod", "FOO=bar\nBAZ=qux")   # str is parsed via dotenv.parse
print(dm.pull_text("work/api", "prod"))            # serialised via dotenv.serialize
```

## Note on canonical form

`dotenv.serialize` (sorted keys, minimal quoting) is a convenience for humans and files. It is
**not** the cryptographic canonical form — that is the canonical JSON in
[`blob.canonical_bytes`](crypto.md#canonical-json-and-content-hash), which is what
`content_hash` is computed over. The two serve different purposes.

## References

- [`client`](client.md) / [`async_client`](async_client.md) — `push`/`push_from_file`
  accept `.env` text; `pull_text`/`pull_to_file` emit it.
- [`crypto`](crypto.md) — the separate canonical-JSON encoding used for encryption and hashing.
