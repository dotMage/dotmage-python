"""Additional client coverage: enroll, from_ci, file helpers, settings seeding, verify."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import httpx
import pytest
import respx
from tests.conftest import BASE, FAST_ARGON, unlocked_client

from dotmage.client import DotMage
from dotmage.core.credentials import Credentials, MemoryStore
from dotmage.core.crypto import blob, keys
from dotmage.exceptions import ContentIntegrityError
from dotmage.settings import Settings


def _keys_route(password: str = "pw") -> None:
    creation = keys.create_account_key_material(password, with_recovery=True, **FAST_ARGON)
    body = asdict(creation.material)
    body["key_gen"] = 1
    respx.get(f"{BASE}/api/v1/account/keys").mock(return_value=httpx.Response(200, json=body))
    _keys_route.account_key = creation.account_key  # type: ignore[attr-defined]


@respx.mock
def test_enroll() -> None:
    respx.post(f"{BASE}/api/v1/auth/device").mock(
        return_value=httpx.Response(
            201,
            json={
                "device_token": "dmage_dtok_e",
                "refresh_token": "dmage_rtok_e",
                "device_id": "d3",
                "token_expires_at": "t",
            },
        )
    )
    _keys_route("pw")
    client = DotMage.enroll(BASE, "dmage_etok_x", "pw", store=MemoryStore())
    assert client.is_unlocked
    assert client._session.account_key == _keys_route.account_key  # type: ignore[attr-defined]


@respx.mock
def test_from_ci() -> None:
    _keys_route("ci-pw")
    store = MemoryStore()
    client = DotMage.from_ci(BASE, "dmage_dtok_ci", "ci-pw", store=store)
    assert client.is_unlocked
    assert store.load().device_token == "dmage_dtok_ci"


def test_seed_credentials_from_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOTMAGE_DEVICE_TOKEN", "dmage_dtok_env")
    monkeypatch.setenv("DOTMAGE_REFRESH_TOKEN", "dmage_rtok_env")
    client = DotMage(BASE, settings=Settings(_env_file=None))
    creds = client._transport.credentials
    assert creds.device_token == "dmage_dtok_env"
    assert creds.refresh_token == "dmage_rtok_env"


def test_server_url_from_store() -> None:
    store = MemoryStore(Credentials(server_url=BASE, device_token="t"))
    client = DotMage(settings=Settings(_env_file=None), store=store)
    assert client.server_url == BASE


@respx.mock
def test_file_helpers(tmp_path: Path) -> None:
    client, account_key = unlocked_client()
    ciphertext, digest = blob.encrypt_blob(account_key, {"A": "1", "B": "two words"})
    respx.get(f"{BASE}/api/v1/apps/app1/envs/prod/revisions/last").mock(
        return_value=httpx.Response(
            200,
            json={
                "rev_number": 1,
                "blob": ciphertext,
                "content_hash": digest,
                "created_at": "t",
                "device_id": "d",
                "key_gen": 1,
            },
        )
    )
    # pull_text renders .env
    text = client.pull_text("app1", "prod")
    assert 'B="two words"' in text
    # pull_to_file writes it
    out = tmp_path / ".env"
    client.pull_to_file("app1", "prod", str(out))
    assert out.read_text(encoding="utf-8") == text
    # get_revision returns the raw model
    assert client.get_revision("app1", "prod").rev_number == 1


@respx.mock
def test_push_from_file(tmp_path: Path) -> None:
    client, account_key = unlocked_client()
    env_file = tmp_path / ".env"
    env_file.write_text("A=1\nB=2\n", encoding="utf-8")
    respx.get(f"{BASE}/api/v1/apps/app1/envs").mock(
        return_value=httpx.Response(
            200,
            json={
                "environments": [
                    {
                        "id": "e",
                        "name": "prod",
                        "latest_rev": 3,
                        "protected": False,
                        "created_at": "t",
                        "updated_at": "t",
                    }
                ]
            },
        )
    )
    captured: dict[str, object] = {}

    def push_handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(201, json={"rev_number": 4, "created_at": "t", "device_id": "d"})

    respx.post(f"{BASE}/api/v1/apps/app1/envs/prod/revisions").mock(side_effect=push_handler)
    result = client.push_from_file("app1", "prod", str(env_file))
    assert result.rev_number == 4
    assert blob.decrypt_blob(account_key, captured["blob"]) == {"A": "1", "B": "2"}


@respx.mock
def test_set_merges(tmp_path: Path) -> None:
    client, account_key = unlocked_client()
    current_blob, current_hash = blob.encrypt_blob(account_key, {"A": "1"})
    respx.get(f"{BASE}/api/v1/apps/app1/envs/prod/revisions/last").mock(
        return_value=httpx.Response(
            200,
            json={
                "rev_number": 2,
                "blob": current_blob,
                "content_hash": current_hash,
                "created_at": "t",
                "device_id": "d",
                "key_gen": 1,
            },
        )
    )
    respx.get(f"{BASE}/api/v1/apps/app1/envs").mock(
        return_value=httpx.Response(
            200,
            json={
                "environments": [
                    {
                        "id": "e",
                        "name": "prod",
                        "latest_rev": 2,
                        "protected": False,
                        "created_at": "t",
                        "updated_at": "t",
                    }
                ]
            },
        )
    )
    captured: dict[str, object] = {}

    def push_handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(201, json={"rev_number": 3, "created_at": "t", "device_id": "d"})

    respx.post(f"{BASE}/api/v1/apps/app1/envs/prod/revisions").mock(side_effect=push_handler)

    client.set("app1", "prod", {"B": "2"})
    merged = blob.decrypt_blob(account_key, captured["blob"])
    assert merged == {"A": "1", "B": "2"}


@respx.mock
def test_set_on_empty_env() -> None:
    client, account_key = unlocked_client()
    respx.get(f"{BASE}/api/v1/apps/app1/envs/prod/revisions/last").mock(
        return_value=httpx.Response(
            404, json={"error": {"code": "RevisionNotFoundError", "message": "No revisions"}}
        )
    )
    respx.get(f"{BASE}/api/v1/apps/app1/envs").mock(
        return_value=httpx.Response(
            200,
            json={
                "environments": [
                    {
                        "id": "e",
                        "name": "prod",
                        "latest_rev": 0,
                        "protected": False,
                        "created_at": "t",
                        "updated_at": "t",
                    }
                ]
            },
        )
    )
    captured: dict[str, object] = {}

    def push_handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(201, json={"rev_number": 1, "created_at": "t", "device_id": "d"})

    respx.post(f"{BASE}/api/v1/apps/app1/envs/prod/revisions").mock(side_effect=push_handler)
    client.set("app1", "prod", {"NEW": "v"})
    assert blob.decrypt_blob(account_key, captured["blob"]) == {"NEW": "v"}


@respx.mock
def test_pull_verify_toggle() -> None:
    client, account_key = unlocked_client()
    ciphertext, _ = blob.encrypt_blob(account_key, {"A": "1"})
    respx.get(f"{BASE}/api/v1/apps/app1/envs/prod/revisions/last").mock(
        return_value=httpx.Response(
            200,
            json={
                "rev_number": 1,
                "blob": ciphertext,
                "content_hash": "deadbeef",
                "created_at": "t",
                "device_id": "d",
                "key_gen": 1,
            },
        )
    )
    # verify=False tolerates a mismatched content hash
    assert client.pull("app1", "prod", verify=False) == {"A": "1"}
    # verify=True (default) enforces it
    with pytest.raises(ContentIntegrityError):
        client.pull("app1", "prod")
