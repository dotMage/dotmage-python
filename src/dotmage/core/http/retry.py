"""Retry policy for the transport layer (tenacity).

Retries both on transient network exceptions and on retryable HTTP status codes. Retryable
statuses are surfaced as a private :class:`_RetryableStatus` exception so a single
tenacity predicate covers both cases; the caller unwraps it to recover the final response.
"""

from __future__ import annotations

import httpx
from tenacity import (
    AsyncRetrying,
    Retrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
    wait_fixed,
)
from tenacity.wait import wait_base

RETRYABLE_STATUS_CODES = frozenset({408, 429, 500, 502, 503, 504})

_RETRYABLE_EXCEPTIONS = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    httpx.RemoteProtocolError,
)


class _RetryableStatus(Exception):
    """Carries a response whose status code is retryable."""

    def __init__(self, response: httpx.Response) -> None:
        super().__init__(f"retryable status {response.status_code}")
        self.response = response


def is_retryable_status(response: httpx.Response) -> bool:
    """Return True if the response status warrants a retry."""
    return response.status_code in RETRYABLE_STATUS_CODES


def _wait(initial: float, maximum: float) -> wait_base:
    if initial <= 0:
        return wait_fixed(0)
    return wait_exponential_jitter(initial=initial, max=maximum)


_retry = retry_if_exception_type((_RetryableStatus, *_RETRYABLE_EXCEPTIONS))


def build_sync_retrying(
    max_attempts: int, *, initial: float = 0.5, maximum: float = 10.0
) -> Retrying:
    """Build a synchronous tenacity ``Retrying`` controller."""
    return Retrying(
        stop=stop_after_attempt(max_attempts),
        wait=_wait(initial, maximum),
        retry=_retry,
        reraise=True,
    )


def build_async_retrying(
    max_attempts: int, *, initial: float = 0.5, maximum: float = 10.0
) -> AsyncRetrying:
    """Build an asynchronous tenacity ``AsyncRetrying`` controller."""
    return AsyncRetrying(
        stop=stop_after_attempt(max_attempts),
        wait=_wait(initial, maximum),
        retry=_retry,
        reraise=True,
    )
