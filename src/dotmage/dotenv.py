"""A small, dependency-free ``.env`` parser and serialiser.

Supports the common subset: ``KEY=VALUE`` lines, ``export KEY=VALUE``, ``#`` comments, blank
lines, and single- or double-quoted values (double quotes honour ``\\n``, ``\\t``, ``\\r``,
``\\\\`` and ``\\"`` escapes). Serialisation quotes values only when necessary and sorts keys
for deterministic output.
"""

from __future__ import annotations

_NEEDS_QUOTING = set(" \t\n\r\"'#=")


def parse(text: str) -> dict[str, str]:
    """Parse ``.env`` text into a dict of string keys and values."""
    result: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key:
            continue
        result[key] = _parse_value(value.strip())
    return result


def _parse_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return _unescape_double(value[1:-1])
    if len(value) >= 2 and value[0] == value[-1] == "'":
        return value[1:-1]
    return value


def _unescape_double(value: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"'}.get(nxt, "\\" + nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def serialize(data: dict[str, str]) -> str:
    """Serialise a dict to ``.env`` text (sorted keys, minimal quoting, trailing newline)."""
    lines = [f"{key}={_format_value(data[key])}" for key in sorted(data)]
    return "\n".join(lines) + "\n" if lines else ""


def _format_value(value: str) -> str:
    if value == "" or any(ch in _NEEDS_QUOTING for ch in value):
        escaped = (
            value.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
        )
        return f'"{escaped}"'
    return value
