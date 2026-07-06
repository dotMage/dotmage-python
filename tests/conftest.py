"""Shared test helpers and fixtures."""

from __future__ import annotations

import httpx
import pytest

from dotmage.async_client import AsyncDotMage
from dotmage.client import DotMage
from dotmage.core.credentials import Credentials, MemoryStore
from dotmage.core.crypto import keys
from dotmage.settings import Settings

BASE = "https://secrets.example.test"

# Fast Argon2 parameters so key-derivation tests stay quick.
FAST_ARGON = {"memory_kib": 8192, "iterations": 2}


def make_client(*, device_token: str = "dmage_dtok_t", refresh_token: str | None = None) -> DotMage:
    """A DotMage bound to a MemoryStore, isolated from the real environment/.env."""
    store = MemoryStore(
        Credentials(server_url=BASE, device_token=device_token, refresh_token=refresh_token)
    )
    return DotMage(BASE, store=store, settings=Settings(_env_file=None), max_retries=1)


def unlocked_client(account_key: bytes | None = None, key_gen: int = 1) -> tuple[DotMage, bytes]:
    """A client whose session already holds an account key (skips network unlock)."""
    account_key = account_key or keys.generate_account_key()
    client = make_client()
    client._session.set_key(account_key, key_gen)
    return client, account_key


def make_async_client(*, device_token: str = "dmage_dtok_t") -> AsyncDotMage:
    """An AsyncDotMage bound to a MemoryStore, isolated from the real environment/.env."""
    store = MemoryStore(Credentials(server_url=BASE, device_token=device_token))
    return AsyncDotMage(BASE, store=store, settings=Settings(_env_file=None), max_retries=1)


def unlocked_async_client(
    account_key: bytes | None = None, key_gen: int = 1
) -> tuple[AsyncDotMage, bytes]:
    """An async client whose session already holds an account key."""
    account_key = account_key or keys.generate_account_key()
    client = make_async_client()
    client._session.set_key(account_key, key_gen)
    return client, account_key


@pytest.fixture
def base_url() -> str:
    return BASE


def json_response(status: int, body: dict[str, object]) -> httpx.Response:
    return httpx.Response(status, json=body)
