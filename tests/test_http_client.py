"""Tests for the sync and async transports (respx-mocked)."""

from __future__ import annotations

import httpx
import pytest
import respx

from dotmage.core.credentials import Credentials, MemoryStore
from dotmage.core.http.client import AsyncTransport, Transport
from dotmage.enums import MethodEnum
from dotmage.exceptions import ConfigError, NotFoundError

BASE = "https://secrets.example.test"


def _transport(**creds: str) -> Transport:
    store = MemoryStore(Credentials(server_url=BASE, **creds))
    return Transport(BASE, store, retry_initial=0, max_attempts=3)


def test_requires_server_url() -> None:
    with pytest.raises(ConfigError):
        Transport("", MemoryStore())


@respx.mock
def test_get_returns_dict_and_sends_bearer() -> None:
    route = respx.get(f"{BASE}/api/v1/apps").mock(
        return_value=httpx.Response(200, json={"apps": []})
    )
    transport = _transport(device_token="dmage_dtok_abc")
    assert transport.request(MethodEnum.GET, "/api/v1/apps") == {"apps": []}
    assert route.calls[0].request.headers["Authorization"] == "Bearer dmage_dtok_abc"
    transport.close()


@respx.mock
def test_error_response_is_mapped() -> None:
    respx.get(f"{BASE}/api/v1/apps/x/envs").mock(
        return_value=httpx.Response(
            404, json={"error": {"code": "AppNotFoundError", "message": "no"}}
        )
    )
    transport = _transport(device_token="t")
    with pytest.raises(NotFoundError) as info:
        transport.request(MethodEnum.GET, "/api/v1/apps/x/envs")
    assert info.value.code == "AppNotFoundError"
    transport.close()


@respx.mock
def test_retries_retryable_status() -> None:
    respx.get(f"{BASE}/api/v1/health").mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json={"status": "ok"})]
    )
    transport = _transport(device_token="t")
    assert transport.request(MethodEnum.GET, "/api/v1/health")["status"] == "ok"
    transport.close()


@respx.mock
def test_auto_refresh_on_401() -> None:
    resource = respx.get(f"{BASE}/api/v1/apps").mock(
        side_effect=[
            httpx.Response(401, json={"error": {"code": "TokenExpiredError", "message": "exp"}}),
            httpx.Response(200, json={"apps": []}),
        ]
    )
    refresh = respx.post(f"{BASE}/api/v1/auth/refresh").mock(
        return_value=httpx.Response(
            200,
            json={
                "device_token": "dmage_dtok_new",
                "refresh_token": "dmage_rtok_new",
                "device_id": "d1",
                "token_expires_at": "2026-08-01T00:00:00Z",
            },
        )
    )
    store = MemoryStore(
        Credentials(server_url=BASE, device_token="old", refresh_token="dmage_rtok_old")
    )
    transport = Transport(BASE, store, retry_initial=0)

    assert transport.request(MethodEnum.GET, "/api/v1/apps") == {"apps": []}
    assert refresh.called
    assert store.load().device_token == "dmage_dtok_new"
    # The retried request used the refreshed token.
    assert resource.calls[-1].request.headers["Authorization"] == "Bearer dmage_dtok_new"
    transport.close()


@respx.mock
def test_no_refresh_token_leaves_401_to_raise() -> None:
    respx.get(f"{BASE}/api/v1/apps").mock(
        return_value=httpx.Response(
            401, json={"error": {"code": "InvalidTokenError", "message": "x"}}
        )
    )
    transport = _transport(device_token="t")  # no refresh token
    with pytest.raises(Exception, match="x"):
        transport.request(MethodEnum.GET, "/api/v1/apps")
    transport.close()


@respx.mock
def test_custom_headers_without_auth() -> None:
    route = respx.post(f"{BASE}/api/v1/auth/device").mock(
        return_value=httpx.Response(201, json={"device_token": "x"})
    )
    transport = _transport(device_token="should-not-be-used")
    transport.request(
        MethodEnum.POST,
        "/api/v1/auth/device",
        json={"device_name": "cli"},
        auth=False,
        headers={"Authorization": "Bearer dmage_etok_enroll"},
    )
    assert route.calls[0].request.headers["Authorization"] == "Bearer dmage_etok_enroll"
    transport.close()


@respx.mock
def test_non_dict_json_is_wrapped() -> None:
    respx.get(f"{BASE}/api/v1/list").mock(return_value=httpx.Response(200, json=[1, 2, 3]))
    transport = _transport(device_token="t")
    assert transport.request(MethodEnum.GET, "/api/v1/list") == {"data": [1, 2, 3]}
    transport.close()


@respx.mock
def test_empty_body_decodes_to_empty_dict() -> None:
    respx.get(f"{BASE}/api/v1/ping").mock(return_value=httpx.Response(200, content=b""))
    transport = _transport(device_token="t")
    assert transport.request(MethodEnum.GET, "/api/v1/ping") == {}
    transport.close()


def test_refresh_without_token_raises() -> None:
    transport = _transport(device_token="t")  # no refresh token
    with pytest.raises(ConfigError):
        transport.refresh()
    transport.close()


@respx.mock
async def test_async_retries_retryable_status() -> None:
    respx.get(f"{BASE}/api/v1/health").mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json={"status": "ok"})]
    )
    store = MemoryStore(Credentials(server_url=BASE, device_token="t"))
    async with AsyncTransport(BASE, store, retry_initial=0) as transport:
        result = await transport.request(MethodEnum.GET, "/api/v1/health")
    assert result["status"] == "ok"


@respx.mock
async def test_async_refresh_without_token_raises() -> None:
    store = MemoryStore(Credentials(server_url=BASE, device_token="t"))
    async with AsyncTransport(BASE, store, retry_initial=0) as transport:
        with pytest.raises(ConfigError):
            await transport.refresh()


@respx.mock
async def test_async_transport_roundtrip() -> None:
    respx.get(f"{BASE}/api/v1/apps").mock(return_value=httpx.Response(200, json={"apps": []}))
    store = MemoryStore(Credentials(server_url=BASE, device_token="t"))
    async with AsyncTransport(BASE, store, retry_initial=0) as transport:
        assert await transport.request(MethodEnum.GET, "/api/v1/apps") == {"apps": []}


@respx.mock
async def test_async_auto_refresh() -> None:
    respx.get(f"{BASE}/api/v1/apps").mock(
        side_effect=[
            httpx.Response(401, json={"error": {"code": "TokenExpiredError", "message": "e"}}),
            httpx.Response(200, json={"apps": []}),
        ]
    )
    respx.post(f"{BASE}/api/v1/auth/refresh").mock(
        return_value=httpx.Response(
            200,
            json={
                "device_token": "new",
                "refresh_token": "rnew",
                "device_id": "d1",
                "token_expires_at": "2026-08-01T00:00:00Z",
            },
        )
    )
    store = MemoryStore(Credentials(server_url=BASE, device_token="old", refresh_token="r"))
    async with AsyncTransport(BASE, store, retry_initial=0) as transport:
        assert await transport.request(MethodEnum.GET, "/api/v1/apps") == {"apps": []}
    assert store.load().device_token == "new"
