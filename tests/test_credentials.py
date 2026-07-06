"""Tests for credential stores."""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

from dotmage.core.credentials import Credentials, FileStore, MemoryStore


def test_credentials_dict_roundtrip_ignores_extra() -> None:
    creds = Credentials.from_dict({"device_token": "t", "unknown": "x"})
    assert creds.device_token == "t"
    assert "unknown" not in creds.to_dict()


def test_memory_store() -> None:
    store = MemoryStore(Credentials(device_token="a"))
    assert store.load().device_token == "a"
    store.save(Credentials(device_token="b"))
    assert store.load().device_token == "b"
    store.clear()
    assert store.load().device_token is None


def test_file_store_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "credentials.json"
    store = FileStore(path)
    assert store.load() == Credentials()  # missing file -> empty

    store.save(Credentials(server_url="https://h", device_token="tok", device_id="d1"))
    assert path.exists()
    loaded = store.load()
    assert loaded.server_url == "https://h"
    assert loaded.device_token == "tok"

    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["device_id"] == "d1"


def test_file_store_permissions(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    FileStore(path).save(Credentials(device_token="tok"))
    if sys.platform != "win32":
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600


def test_file_store_default_path() -> None:
    store = FileStore()
    assert store.path.name == "credentials.json"
    assert "dotmage" in str(store.path)
