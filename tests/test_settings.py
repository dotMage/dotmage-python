"""Tests for SDK settings."""

from __future__ import annotations

import pytest

from dotmage.settings import Settings, get_settings


def test_defaults() -> None:
    settings = Settings(_env_file=None)
    assert settings.SERVER_URL is None
    assert settings.TIMEOUT == 10.0
    assert settings.MAX_RETRIES == 5


def test_reads_prefixed_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOTMAGE_SERVER_URL", "https://secrets.example.com")
    monkeypatch.setenv("DOTMAGE_MASTER_PASSWORD", "hunter2")
    settings = Settings(_env_file=None)
    assert settings.SERVER_URL == "https://secrets.example.com"
    assert settings.MASTER_PASSWORD is not None
    assert settings.MASTER_PASSWORD.get_secret_value() == "hunter2"
    # Secret is not leaked in the repr.
    assert "hunter2" not in repr(settings)


def test_get_settings_is_cached() -> None:
    get_settings.cache_clear()
    assert get_settings() is get_settings()
    get_settings.cache_clear()
