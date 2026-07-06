"""Tests for the retry policy."""

from __future__ import annotations

import httpx
import pytest

from dotmage.core.http.retry import (
    RETRYABLE_STATUS_CODES,
    build_sync_retrying,
    is_retryable_status,
)


def test_is_retryable_status() -> None:
    assert is_retryable_status(httpx.Response(503))
    assert is_retryable_status(httpx.Response(429))
    assert not is_retryable_status(httpx.Response(404))
    assert 500 in RETRYABLE_STATUS_CODES


def test_retries_transient_exception_then_succeeds() -> None:
    retrying = build_sync_retrying(3, initial=0)
    calls = {"n": 0}

    def fn() -> str:
        calls["n"] += 1
        if calls["n"] < 3:
            raise httpx.ConnectError("boom")
        return "ok"

    assert retrying(fn) == "ok"
    assert calls["n"] == 3


def test_non_retryable_exception_propagates_immediately() -> None:
    retrying = build_sync_retrying(3, initial=0)
    calls = {"n": 0}

    def fn() -> str:
        calls["n"] += 1
        raise ValueError("nope")

    with pytest.raises(ValueError, match="nope"):
        retrying(fn)
    assert calls["n"] == 1


def test_gives_up_after_max_attempts() -> None:
    retrying = build_sync_retrying(2, initial=0)
    calls = {"n": 0}

    def fn() -> str:
        calls["n"] += 1
        raise httpx.ReadTimeout("slow")

    with pytest.raises(httpx.ReadTimeout):
        retrying(fn)
    assert calls["n"] == 2
