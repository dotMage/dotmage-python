"""End-to-end flow tests for the asynchronous AsyncDotMage client."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import httpx
import pytest
import respx
from tests.conftest import BASE, FAST_ARGON, make_async_client, unlocked_async_client

from dotmage.async_client import AsyncDotMage
from dotmage.core.credentials import MemoryStore
from dotmage.core.crypto import blob, keys
from dotmage.exceptions import (
    ConfigError,
    ContentIntegrityError,
    NotFoundError,
    RevisionConflictError,
)
from dotmage.settings import Settings

ENV = {
    "id": "e1",
    "name": "prod",
    "latest_rev": 4,
    "protected": False,
    "created_at": "t",
    "updated_at": "t",
}


def _keys_body(password: str) -> dict[str, object]:
    creation = keys.create_account_key_material(password, with_recovery=True, **FAST_ARGON)
    body = asdict(creation.material)
    body["key_gen"] = 1
    return body, creation  # type: ignore[return-value]


def test_requires_server_url() -> None:
    with pytest.raises(ConfigError):
        AsyncDotMage(settings=Settings(_env_file=None), store=MemoryStore())


@respx.mock
async def test_health_and_whoami() -> None:
    respx.get(f"{BASE}/health").mock(
        return_value=httpx.Response(
            200, json={"status": "ok", "version": "0.2.0", "account_exists": True}
        )
    )
    respx.get(f"{BASE}/api/v1/whoami").mock(
        return_value=httpx.Response(
            200,
            json={
                "user_id": "u1",
                "name": "owner",
                "role": "owner",
                "device_id": "d1",
                "device_name": "laptop",
            },
        )
    )
    async with make_async_client() as client:
        assert (await client.health()).status == "ok"
        assert (await client.whoami()).role == "owner"


@respx.mock
async def test_init_vault_and_unlock() -> None:
    respx.post(f"{BASE}/api/v1/account/init").mock(
        return_value=httpx.Response(
            201,
            json={
                "device_token": "dmage_dtok_x",
                "refresh_token": "dmage_rtok_y",
                "device_id": "d1",
                "token_expires_at": "t",
            },
        )
    )
    client, recovery = await AsyncDotMage.init_vault(BASE, "BOOT", "pw", store=MemoryStore())
    assert client.is_unlocked
    assert recovery is not None
    await client.aclose()


@respx.mock
async def test_enroll_and_unlock_roundtrip() -> None:
    body, creation = _keys_body("pw")
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
    respx.get(f"{BASE}/api/v1/account/keys").mock(return_value=httpx.Response(200, json=body))
    client = await AsyncDotMage.enroll(BASE, "dmage_etok_x", "pw", store=MemoryStore())
    assert client._session.account_key == creation.account_key
    # recovery unlock path
    client.lock()
    await client.unlock_with_recovery(creation.recovery_code)
    assert client.is_unlocked
    await client.aclose()


@respx.mock
async def test_from_ci() -> None:
    body, _ = _keys_body("ci")
    respx.get(f"{BASE}/api/v1/account/keys").mock(return_value=httpx.Response(200, json=body))
    client = await AsyncDotMage.from_ci(BASE, "dmage_dtok_ci", "ci", store=MemoryStore())
    assert client.is_unlocked
    await client.aclose()


@respx.mock
async def test_change_master_password() -> None:
    body, _ = _keys_body("old")
    respx.get(f"{BASE}/api/v1/account/keys").mock(return_value=httpx.Response(200, json=body))
    respx.patch(f"{BASE}/api/v1/account/keys").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    client = make_async_client()
    await client.change_master_password("old", "new")
    await client.aclose()


@respx.mock
async def test_apps_envs_and_secrets() -> None:
    client, _ = unlocked_async_client()
    respx.get(f"{BASE}/api/v1/apps").mock(return_value=httpx.Response(200, json={"apps": []}))
    respx.post(f"{BASE}/api/v1/apps").mock(
        return_value=httpx.Response(
            201, json={"id": "a", "name": "app1", "created_at": "t", "updated_at": "t"}
        )
    )
    respx.delete(f"{BASE}/api/v1/apps/app1").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    respx.get(f"{BASE}/api/v1/apps/app1/envs").mock(
        return_value=httpx.Response(200, json={"environments": [ENV]})
    )
    respx.post(f"{BASE}/api/v1/apps/app1/envs").mock(return_value=httpx.Response(201, json=ENV))
    respx.delete(f"{BASE}/api/v1/apps/app1/envs/prod").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )

    assert await client.list_apps() == []
    assert (await client.create_app("app1")).name == "app1"
    await client.delete_app("app1")
    assert (await client.list_envs("app1"))[0].name == "prod"
    assert (await client.create_env("app1", "prod")).name == "prod"
    await client.delete_env("app1", "prod")

    captured: dict[str, object] = {}

    def push_handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(201, json={"rev_number": 5, "created_at": "t", "device_id": "d"})

    respx.post(f"{BASE}/api/v1/apps/app1/envs/prod/revisions").mock(side_effect=push_handler)
    result = await client.push("app1", "prod", {"A": "1"})
    assert result.rev_number == 5
    assert captured["parent_rev"] == 4

    def get_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "rev_number": 5,
                "blob": captured["blob"],
                "content_hash": captured["content_hash"],
                "created_at": "t",
                "device_id": "d",
                "key_gen": 1,
            },
        )

    respx.get(f"{BASE}/api/v1/apps/app1/envs/prod/revisions/last").mock(side_effect=get_handler)
    assert await client.pull("app1", "prod") == {"A": "1"}
    assert "A=1" in await client.pull_text("app1", "prod")
    assert (await client.get_revision("app1", "prod")).rev_number == 5
    await client.aclose()


@respx.mock
async def test_pull_to_file_and_push_from_file(tmp_path: Path) -> None:
    client, account_key = unlocked_async_client()
    ciphertext, digest = blob.encrypt_blob(account_key, {"A": "1"})
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
    out = tmp_path / ".env"
    await client.pull_to_file("app1", "prod", str(out))
    assert out.read_text(encoding="utf-8") == "A=1\n"

    respx.get(f"{BASE}/api/v1/apps/app1/envs").mock(
        return_value=httpx.Response(200, json={"environments": [{**ENV, "latest_rev": 1}]})
    )
    respx.post(f"{BASE}/api/v1/apps/app1/envs/prod/revisions").mock(
        return_value=httpx.Response(
            201, json={"rev_number": 2, "created_at": "t", "device_id": "d"}
        )
    )
    assert (await client.push_from_file("app1", "prod", str(out))).rev_number == 2
    await client.aclose()


@respx.mock
async def test_set_and_verify_and_conflict() -> None:
    client, account_key = unlocked_async_client()
    cur_blob, _ = blob.encrypt_blob(account_key, {"A": "1"})
    respx.get(f"{BASE}/api/v1/apps/app1/envs/prod/revisions/last").mock(
        return_value=httpx.Response(
            200,
            json={
                "rev_number": 1,
                "blob": cur_blob,
                "content_hash": "wrong",
                "created_at": "t",
                "device_id": "d",
                "key_gen": 1,
            },
        )
    )
    # verify=False tolerates mismatch; verify=True raises
    assert await client.pull("app1", "prod", verify=False) == {"A": "1"}
    with pytest.raises(ContentIntegrityError):
        await client.pull("app1", "prod")

    respx.get(f"{BASE}/api/v1/apps/app1/envs").mock(
        return_value=httpx.Response(200, json={"environments": [{**ENV, "latest_rev": 1}]})
    )
    # set() pulls (verify default) -> fails on 'wrong'; use a good hash instead
    good_blob, good_hash = blob.encrypt_blob(account_key, {"A": "1"})
    respx.get(f"{BASE}/api/v1/apps/app1/envs/prod/revisions/last").mock(
        return_value=httpx.Response(
            200,
            json={
                "rev_number": 1,
                "blob": good_blob,
                "content_hash": good_hash,
                "created_at": "t",
                "device_id": "d",
                "key_gen": 1,
            },
        )
    )
    respx.post(f"{BASE}/api/v1/apps/app1/envs/prod/revisions").mock(
        return_value=httpx.Response(
            409,
            json={
                "error": {
                    "code": "RevisionConflictError",
                    "message": "Remote is ahead (server rev 9, your parent 1)",
                }
            },
        )
    )
    with pytest.raises(RevisionConflictError) as info:
        await client.set("app1", "prod", {"B": "2"})
    assert info.value.server_rev == 9
    await client.aclose()


@respx.mock
async def test_missing_env_and_diff_and_status() -> None:
    client, account_key = unlocked_async_client()
    respx.get(f"{BASE}/api/v1/apps/app1/envs").mock(
        return_value=httpx.Response(200, json={"environments": []})
    )
    with pytest.raises(NotFoundError):
        await client.push("app1", "prod", {"A": "1"})

    blob_a, hash_a = blob.encrypt_blob(account_key, {"A": "1"})
    blob_b, hash_b = blob.encrypt_blob(account_key, {"A": "2", "B": "3"})
    respx.get(f"{BASE}/api/v1/apps/app1/envs/prod/revisions/1").mock(
        return_value=httpx.Response(
            200,
            json={
                "rev_number": 1,
                "blob": blob_a,
                "content_hash": hash_a,
                "created_at": "t",
                "device_id": "d",
                "key_gen": 1,
            },
        )
    )
    respx.get(f"{BASE}/api/v1/apps/app1/envs/prod/revisions/last").mock(
        return_value=httpx.Response(
            200,
            json={
                "rev_number": 2,
                "blob": blob_b,
                "content_hash": hash_b,
                "created_at": "t",
                "device_id": "d",
                "key_gen": 1,
            },
        )
    )
    diff = await client.diff("app1", "prod", 1)
    assert {c.key for c in diff.added} == {"B"}

    respx.get(f"{BASE}/api/v1/apps/app1/envs/prod/revisions").mock(
        return_value=httpx.Response(
            200,
            json={
                "revisions": [
                    {"rev_number": 2, "content_hash": hash_b, "created_at": "t", "device_id": "d"}
                ]
            },
        )
    )
    assert (await client.status("app1", "prod", {"A": "2", "B": "3"})).state.value == "synced"
    assert (await client.list_revisions("app1", "prod"))[0].rev_number == 2
    await client.aclose()


@respx.mock
async def test_status_no_remote_and_rollback() -> None:
    client, _ = unlocked_async_client()
    respx.get(f"{BASE}/api/v1/apps/app1/envs/prod/revisions").mock(
        return_value=httpx.Response(200, json={"revisions": []})
    )
    assert (await client.status("app1", "prod", {"A": "1"})).state.value == "no_remote"
    respx.post(f"{BASE}/api/v1/apps/app1/envs/prod/rollback").mock(
        return_value=httpx.Response(201, json={"rev_number": 3, "copied_from": 1})
    )
    assert (await client.rollback("app1", "prod", 1)).copied_from == 1
    await client.aclose()


@respx.mock
async def test_devices_and_team_and_audit() -> None:
    client, _ = unlocked_async_client()
    respx.get(f"{BASE}/api/v1/devices").mock(
        return_value=httpx.Response(
            200,
            json={
                "devices": [
                    {
                        "id": "d1",
                        "name": "l",
                        "last_seen": None,
                        "expires_at": "t",
                        "revoked": False,
                        "created_at": "t",
                        "allowed_app": None,
                        "allowed_env": None,
                    }
                ]
            },
        )
    )
    respx.delete(f"{BASE}/api/v1/devices/d1").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    respx.post(f"{BASE}/api/v1/devices/enroll-token").mock(
        return_value=httpx.Response(201, json={"token": "dmage_etok_z", "expires_at": "t"})
    )
    respx.post(f"{BASE}/api/v1/devices/ci-token").mock(
        return_value=httpx.Response(
            201,
            json={
                "device_token": "dmage_dtok_ci",
                "refresh_token": "r",
                "device_id": "d2",
                "expires_at": "t",
            },
        )
    )
    respx.get(f"{BASE}/api/v1/users").mock(
        return_value=httpx.Response(200, json={"users": [], "invitations": []})
    )
    respx.post(f"{BASE}/api/v1/users/invite").mock(
        return_value=httpx.Response(201, json={"invitation_id": "inv1", "expires_at": "t"})
    )
    respx.patch(f"{BASE}/api/v1/users/u2").mock(
        return_value=httpx.Response(200, json={"id": "u2", "name": "k", "role": "viewer"})
    )
    respx.delete(f"{BASE}/api/v1/users/u2").mock(
        return_value=httpx.Response(
            200, json={"id": "u2", "name": "k", "devices_revoked": 1, "rotation_required": True}
        )
    )
    respx.get(f"{BASE}/api/v1/audit").mock(
        return_value=httpx.Response(
            200,
            json={
                "events": [
                    {
                        "id": "1",
                        "device_id": "d",
                        "user": "o",
                        "action": "push",
                        "app_name": "a",
                        "env_name": "e",
                        "rev_number": 1,
                        "at": "t",
                    }
                ]
            },
        )
    )

    assert (await client.list_devices())[0].name == "l"
    await client.revoke_device("d1")
    assert (await client.gen_enroll_token()).token == "dmage_etok_z"
    assert (await client.gen_ci_token("a", "e")).device_token == "dmage_dtok_ci"
    assert (await client.list_users()).users == []
    payload = await client.invite("kolya")
    assert payload.invitation_id == "inv1"
    await client.change_role("u2", "viewer")
    assert (await client.remove_user("u2")).rotation_required is True
    assert (await client.audit(app="a"))[0].action == "push"
    await client.aclose()


@respx.mock
async def test_join_roundtrip() -> None:
    inviter, account_key = unlocked_async_client()
    captured: dict[str, object] = {}

    def invite_handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(201, json={"invitation_id": "inv1", "expires_at": "t"})

    respx.post(f"{BASE}/api/v1/users/invite").mock(side_effect=invite_handler)
    payload = await inviter.invite("kolya")

    respx.post(f"{BASE}/api/v1/invitations/redeem").mock(
        return_value=httpx.Response(
            200,
            json={
                "sealed_ak": captured["sealed_ak"],
                "nonce_inv": captured["nonce_inv"],
                "key_gen": 1,
                "name": "kolya",
                "role": "editor",
                "argon_defaults": {
                    "memory": 8192,
                    "iterations": 2,
                    "parallelism": 1,
                    "version": 19,
                },
            },
        )
    )
    respx.post(f"{BASE}/api/v1/invitations/complete").mock(
        return_value=httpx.Response(
            201,
            json={
                "user_id": "u2",
                "device_id": "d2",
                "device_token": "dmage_dtok_j",
                "refresh_token": "r",
                "expires_at": "t",
            },
        )
    )
    joiner, recovery = await AsyncDotMage.join(
        BASE, payload.invitation_id, payload.redeem_secret, "pw", store=MemoryStore()
    )
    assert joiner._session.account_key == account_key
    assert recovery is not None
    await inviter.aclose()
    await joiner.aclose()


@respx.mock
async def test_rotate() -> None:
    client, old_key = unlocked_async_client()
    creation = keys.create_account_key_material("rot", with_recovery=False, **FAST_ARGON)
    keys_body = asdict(creation.material)
    keys_body["key_gen"] = 1
    stale_blob, stale_hash = blob.encrypt_blob(old_key, {"S": "v"})

    respx.get(f"{BASE}/api/v1/account/keys").mock(return_value=httpx.Response(200, json=keys_body))
    respx.get(f"{BASE}/api/v1/account/rotate").mock(
        side_effect=[
            httpx.Response(200, json={"in_progress": False, "current_key_gen": 1}),
            httpx.Response(
                200,
                json={
                    "in_progress": True,
                    "current_key_gen": 1,
                    "new_key_gen": 2,
                    "stale_count": 1,
                    "stale": [{"app": "a", "env": "prod", "rev_number": 1}],
                },
            ),
            httpx.Response(
                200,
                json={
                    "in_progress": True,
                    "current_key_gen": 1,
                    "new_key_gen": 2,
                    "stale_count": 0,
                    "stale": [],
                },
            ),
        ]
    )
    respx.post(f"{BASE}/api/v1/account/rotate/begin").mock(
        return_value=httpx.Response(200, json={"new_key_gen": 2, "stale_count": 1})
    )
    respx.get(f"{BASE}/api/v1/apps/a/envs/prod/revisions/1").mock(
        return_value=httpx.Response(
            200,
            json={
                "rev_number": 1,
                "blob": stale_blob,
                "content_hash": stale_hash,
                "created_at": "t",
                "device_id": "d",
                "key_gen": 1,
            },
        )
    )
    put_captured: dict[str, object] = {}

    def put_handler(request: httpx.Request) -> httpx.Response:
        put_captured.update(json.loads(request.content))
        return httpx.Response(200, json={"rev_number": 1, "key_gen": 2})

    respx.put(f"{BASE}/api/v1/apps/a/envs/prod/revisions/1/blob").mock(side_effect=put_handler)
    respx.post(f"{BASE}/api/v1/account/rotate/complete").mock(
        return_value=httpx.Response(200, json={"current_key_gen": 2})
    )

    seen: list[tuple[int, int]] = []
    recovery = await client.rotate("rot", progress=lambda d, t: seen.append((d, t)))
    assert recovery is None
    assert client._session.key_gen == 2
    assert blob.decrypt_blob(client._session.account_key, put_captured["blob"]) == {"S": "v"}
    assert seen == [(1, 1)]
    await client.aclose()
