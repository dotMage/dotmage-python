"""HTTP transport: authenticated, retrying request helpers over httpx.

A :class:`Transport` (sync) / :class:`AsyncTransport` (async) owns an httpx client, a
credential store, and a retry controller. It injects the device token, transparently refreshes
an expired token once on ``401``, retries transient failures, and maps error responses to the
SDK exception hierarchy. Successful responses are returned as decoded JSON dicts.
"""

from __future__ import annotations

from types import TracebackType
from typing import Any

import httpx
from loguru import logger

from dotmage.core.credentials.base import Credentials, CredentialStore
from dotmage.core.credentials.memory import MemoryStore
from dotmage.core.http.retry import (
    _RetryableStatus,
    build_async_retrying,
    build_sync_retrying,
    is_retryable_status,
)
from dotmage.enums import MethodEnum
from dotmage.exceptions import ConfigError, error_from_response

_REFRESH_PATH = "/api/v1/auth/refresh"
_DEFAULT_LIMITS = httpx.Limits(max_connections=100, max_keepalive_connections=20)


def _build_headers(token: str | None, extra: dict[str, str] | None) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra:
        headers.update(extra)
    return headers


def _decode(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {"data": body}


class _BaseTransport:
    def __init__(
        self,
        server_url: str,
        store: CredentialStore | None = None,
        *,
        timeout: float = 10.0,
        max_attempts: int = 5,
        retry_initial: float = 0.5,
        retry_max: float = 10.0,
    ) -> None:
        if not server_url:
            raise ConfigError("a server URL is required")
        self.server_url = server_url.rstrip("/")
        self.store = store or MemoryStore()
        self._timeout = timeout
        self._max_attempts = max_attempts
        self._retry_initial = retry_initial
        self._retry_max = retry_max

    @property
    def credentials(self) -> Credentials:
        return self.store.load()

    def _can_refresh(self) -> bool:
        return bool(self.credentials.refresh_token)

    def _apply_refresh(self, payload: dict[str, Any]) -> None:
        creds = self.credentials
        creds.device_token = payload["device_token"]
        creds.refresh_token = payload["refresh_token"]
        creds.device_id = payload.get("device_id", creds.device_id)
        creds.expires_at = payload.get("token_expires_at", creds.expires_at)
        self.store.save(creds)

    def _handle(self, response: httpx.Response) -> dict[str, Any]:
        if response.status_code >= 400:
            raise error_from_response(response.status_code, _decode(response))
        return _decode(response)


class Transport(_BaseTransport):
    """Synchronous transport."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._client = httpx.Client(
            base_url=self.server_url,
            timeout=httpx.Timeout(self._timeout),
            limits=_DEFAULT_LIMITS,
        )
        self._retrying = build_sync_retrying(
            self._max_attempts, initial=self._retry_initial, maximum=self._retry_max
        )

    def request(
        self,
        method: MethodEnum,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        auth: bool = True,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a request, refreshing once on 401, and return the decoded JSON body."""
        response = self._send(method, path, json=json, params=params, auth=auth, headers=headers)
        if response.status_code == 401 and auth and self._can_refresh():
            logger.debug("401 received; attempting token refresh")
            self.refresh()
            response = self._send(
                method, path, json=json, params=params, auth=auth, headers=headers
            )
        return self._handle(response)

    def refresh(self) -> None:
        """Rotate the device/refresh tokens using the stored refresh token."""
        token = self.credentials.refresh_token
        if not token:
            raise ConfigError("no refresh token available")
        response = self._send(
            MethodEnum.POST, _REFRESH_PATH, json={"refresh_token": token}, auth=False
        )
        self._apply_refresh(self._handle(response))

    def _send(
        self,
        method: MethodEnum,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        auth: bool = True,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        token = self.credentials.device_token if auth else None
        request_headers = _build_headers(token, headers)

        def _once() -> httpx.Response:
            logger.debug("{method} {path}", method=method.value, path=path)
            response = self._client.request(
                method.value, path, json=json, params=params, headers=request_headers
            )
            if is_retryable_status(response):
                raise _RetryableStatus(response)
            return response

        try:
            return self._retrying(_once)
        except _RetryableStatus as exc:
            return exc.response

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Transport:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class AsyncTransport(_BaseTransport):
    """Asynchronous transport."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._client = httpx.AsyncClient(
            base_url=self.server_url,
            timeout=httpx.Timeout(self._timeout),
            limits=_DEFAULT_LIMITS,
        )
        self._retrying = build_async_retrying(
            self._max_attempts, initial=self._retry_initial, maximum=self._retry_max
        )

    async def request(
        self,
        method: MethodEnum,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        auth: bool = True,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a request, refreshing once on 401, and return the decoded JSON body."""
        response = await self._send(
            method, path, json=json, params=params, auth=auth, headers=headers
        )
        if response.status_code == 401 and auth and self._can_refresh():
            logger.debug("401 received; attempting token refresh")
            await self.refresh()
            response = await self._send(
                method, path, json=json, params=params, auth=auth, headers=headers
            )
        return self._handle(response)

    async def refresh(self) -> None:
        """Rotate the device/refresh tokens using the stored refresh token."""
        token = self.credentials.refresh_token
        if not token:
            raise ConfigError("no refresh token available")
        response = await self._send(
            MethodEnum.POST, _REFRESH_PATH, json={"refresh_token": token}, auth=False
        )
        self._apply_refresh(self._handle(response))

    async def _send(
        self,
        method: MethodEnum,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        auth: bool = True,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        token = self.credentials.device_token if auth else None
        request_headers = _build_headers(token, headers)

        async def _once() -> httpx.Response:
            logger.debug("{method} {path}", method=method.value, path=path)
            response = await self._client.request(
                method.value, path, json=json, params=params, headers=request_headers
            )
            if is_retryable_status(response):
                raise _RetryableStatus(response)
            return response

        try:
            return await self._retrying(_once)
        except _RetryableStatus as exc:
            return exc.response

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> AsyncTransport:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()
