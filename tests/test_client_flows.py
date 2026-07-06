"""End-to-end flow tests for the synchronous DotMage client (respx-mocked server)."""

from __future__ import annotations

import json
from dataclasses import asdict

import httpx
import pytest
import respx
from tests.conftest import BASE, FAST_ARGON, make_client, unlocked_client

from dotmage.client import DotMage
from dotmage.core.credentials import MemoryStore
from dotmage.core.crypto import blob, keys, suite
from dotmage.exceptions import ConfigError, NotFoundError, RevisionConflictError
from dotmage.settings import Settings


def test_requires_server_url() -> None:
    with pytest.raises(ConfigError):
        DotMage(settings=Settings(_env_file=None), store=MemoryStore())


@respx.mock
def test_health() -> None:
    respx.get(f"{BASE}/health").mock(
        return_value=httpx.Response(
            200,
            json={
                "status": "ok",
                "version": "0.2.0",
                "account_exists": True,
                "features": ["rotation", "team"],
            },
        )
    )
    health = make_client().health()
    assert health.account_exists
    assert "team" in health.features


@respx.mock
def test_init_vault_sends_crypto_and_unlocks() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(
            201,
            json={
                "device_token": "dmage_dtok_x",
                "refresh_token": "dmage_rtok_y",
                "device_id": "d1",
                "token_expires_at": "2026-08-01T00:00:00Z",
            },
        )

    respx.post(f"{BASE}/api/v1/account/init").mock(side_effect=handler)

    store = MemoryStore()
    client, recovery = DotMage.init_vault(
        BASE, "BOOT", "master-pw", store=store, device_name="laptop"
    )
    assert client.is_unlocked
    assert recovery is not None
    assert captured["bootstrap_secret"] == "BOOT"
    assert captured["device_name"] == "laptop"
    assert "wrapped_ak" in captured and "nonce_ak" in captured
    assert store.load().device_token == "dmage_dtok_x"


@respx.mock
def test_unlock_roundtrip() -> None:
    creation = keys.create_account_key_material("master-pw", with_recovery=True, **FAST_ARGON)
    keys_body = asdict(creation.material)
    keys_body["key_gen"] = 1
    respx.get(f"{BASE}/api/v1/account/keys").mock(return_value=httpx.Response(200, json=keys_body))

    client = make_client()
    client.unlock("master-pw")
    assert client.is_unlocked
    assert client._session.account_key == creation.account_key


@respx.mock
def test_unlock_with_recovery() -> None:
    creation = keys.create_account_key_material("master-pw", with_recovery=True, **FAST_ARGON)
    keys_body = asdict(creation.material)
    keys_body["key_gen"] = 1
    respx.get(f"{BASE}/api/v1/account/keys").mock(return_value=httpx.Response(200, json=keys_body))

    client = make_client()
    assert creation.recovery_code is not None
    client.unlock_with_recovery(creation.recovery_code)
    assert client._session.account_key == creation.account_key


@respx.mock
def test_apps_and_envs() -> None:
    respx.get(f"{BASE}/api/v1/apps").mock(
        return_value=httpx.Response(
            200,
            json={
                "apps": [
                    {
                        "id": "a1",
                        "name": "app1",
                        "created_at": "t",
                        "updated_at": "t",
                        "environments": [],
                    }
                ]
            },
        )
    )
    respx.post(f"{BASE}/api/v1/apps").mock(
        return_value=httpx.Response(
            201, json={"id": "a1", "name": "app1", "created_at": "t", "updated_at": "t"}
        )
    )
    respx.post(f"{BASE}/api/v1/apps/app1/envs").mock(
        return_value=httpx.Response(
            201,
            json={
                "id": "e1",
                "name": "prod",
                "latest_rev": 0,
                "protected": False,
                "created_at": "t",
                "updated_at": "t",
            },
        )
    )
    respx.delete(f"{BASE}/api/v1/apps/app1/envs/prod").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    respx.delete(f"{BASE}/api/v1/apps/app1").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )

    client = make_client()
    assert client.list_apps()[0].name == "app1"
    assert client.create_app("app1").name == "app1"
    assert client.create_env("app1", "prod").name == "prod"
    client.delete_env("app1", "prod")
    client.delete_app("app1")


@respx.mock
def test_push_and_pull_roundtrip() -> None:
    client, _ = unlocked_client()
    captured: dict[str, object] = {}

    respx.get(f"{BASE}/api/v1/apps/app1/envs").mock(
        return_value=httpx.Response(
            200,
            json={
                "environments": [
                    {
                        "id": "e1",
                        "name": "prod",
                        "latest_rev": 4,
                        "protected": False,
                        "created_at": "t",
                        "updated_at": "t",
                    }
                ]
            },
        )
    )

    def push_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        captured.update(body)
        return httpx.Response(
            201, json={"rev_number": body["parent_rev"] + 1, "created_at": "t", "device_id": "d1"}
        )

    respx.post(f"{BASE}/api/v1/apps/app1/envs/prod/revisions").mock(side_effect=push_handler)

    result = client.push("app1", "prod", {"DATABASE_URL": "postgres://x"})
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
                "device_id": "d1",
                "key_gen": 1,
            },
        )

    respx.get(f"{BASE}/api/v1/apps/app1/envs/prod/revisions/last").mock(side_effect=get_handler)
    assert client.pull("app1", "prod") == {"DATABASE_URL": "postgres://x"}


@respx.mock
def test_push_conflict_raises() -> None:
    client, _ = unlocked_client()
    respx.get(f"{BASE}/api/v1/apps/app1/envs").mock(
        return_value=httpx.Response(
            200,
            json={
                "environments": [
                    {
                        "id": "e1",
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
    respx.post(f"{BASE}/api/v1/apps/app1/envs/prod/revisions").mock(
        return_value=httpx.Response(
            409,
            json={
                "error": {
                    "code": "RevisionConflictError",
                    "message": "Remote is ahead (server rev 7, your parent 2)",
                }
            },
        )
    )
    with pytest.raises(RevisionConflictError) as info:
        client.push("app1", "prod", {"A": "1"})
    assert info.value.server_rev == 7


@respx.mock
def test_push_with_explicit_base_rev_skips_lookup() -> None:
    client, _ = unlocked_client()
    respx.post(f"{BASE}/api/v1/apps/app1/envs/prod/revisions").mock(
        return_value=httpx.Response(
            201, json={"rev_number": 4, "created_at": "t", "device_id": "d"}
        )
    )
    result = client.push("app1", "prod", {"A": "1"}, base_rev=3)
    assert result.rev_number == 4


@respx.mock
def test_latest_rev_missing_env() -> None:
    client, _ = unlocked_client()
    respx.get(f"{BASE}/api/v1/apps/app1/envs").mock(
        return_value=httpx.Response(200, json={"environments": []})
    )
    with pytest.raises(NotFoundError):
        client.push("app1", "prod", {"A": "1"})


@respx.mock
def test_diff() -> None:
    client, account_key = unlocked_client()
    blob_a, hash_a = blob.encrypt_blob(account_key, {"A": "1", "OLD": "x"})
    blob_b, hash_b = blob.encrypt_blob(account_key, {"A": "2", "NEW": "y"})

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
                "rev_number": 3,
                "blob": blob_b,
                "content_hash": hash_b,
                "created_at": "t",
                "device_id": "d",
                "key_gen": 1,
            },
        )
    )
    diff = client.diff("app1", "prod", 1)
    assert {c.key for c in diff.added} == {"NEW"}
    assert {c.key for c in diff.removed} == {"OLD"}
    assert {c.key for c in diff.changed} == {"A"}


@respx.mock
def test_status_drift() -> None:
    client, account_key = unlocked_client()
    _, remote_hash = blob.encrypt_blob(account_key, {"A": "1"})
    respx.get(f"{BASE}/api/v1/apps/app1/envs/prod/revisions").mock(
        return_value=httpx.Response(
            200,
            json={
                "revisions": [
                    {
                        "rev_number": 1,
                        "content_hash": remote_hash,
                        "created_at": "t",
                        "device_id": "d",
                    }
                ]
            },
        )
    )
    synced = client.status("app1", "prod", {"A": "1"})
    assert synced.state.value == "synced"
    diverged = client.status("app1", "prod", {"A": "2"})
    assert diverged.state.value == "diverged"


@respx.mock
def test_status_no_remote() -> None:
    client, _ = unlocked_client()
    respx.get(f"{BASE}/api/v1/apps/app1/envs/prod/revisions").mock(
        return_value=httpx.Response(200, json={"revisions": []})
    )
    drift = client.status("app1", "prod", {"A": "1"})
    assert drift.state.value == "no_remote"


@respx.mock
def test_rollback_and_list_revisions() -> None:
    client, _ = unlocked_client()
    respx.get(f"{BASE}/api/v1/apps/app1/envs/prod/revisions").mock(
        return_value=httpx.Response(
            200,
            json={"revisions": [{"rev_number": 1, "created_at": "t", "device_id": "d"}]},
        )
    )
    respx.post(f"{BASE}/api/v1/apps/app1/envs/prod/rollback").mock(
        return_value=httpx.Response(201, json={"rev_number": 3, "copied_from": 1})
    )
    assert client.list_revisions("app1", "prod")[0].rev_number == 1
    assert client.rollback("app1", "prod", 1).copied_from == 1


@respx.mock
def test_devices() -> None:
    client = make_client()
    respx.get(f"{BASE}/api/v1/devices").mock(
        return_value=httpx.Response(
            200,
            json={
                "devices": [
                    {
                        "id": "d1",
                        "name": "laptop",
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
                "refresh_token": "dmage_rtok_ci",
                "device_id": "d2",
                "expires_at": "t",
            },
        )
    )
    assert client.list_devices()[0].name == "laptop"
    client.revoke_device("d1")
    assert client.gen_enroll_token().token == "dmage_etok_z"
    assert client.gen_ci_token("app1", "prod").device_token == "dmage_dtok_ci"


@respx.mock
def test_invite_and_join_roundtrip() -> None:
    inviter, account_key = unlocked_client()
    captured: dict[str, object] = {}

    def invite_handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(201, json={"invitation_id": "inv1", "expires_at": "t"})

    respx.post(f"{BASE}/api/v1/users/invite").mock(side_effect=invite_handler)
    payload = inviter.invite("kolya", role="editor")
    assert payload.invitation_id == "inv1"
    assert "sealed_ak" in captured

    # The invitee opens the sealed AK the inviter created, then completes.
    sealed_ak = captured["sealed_ak"]
    nonce_inv = captured["nonce_inv"]
    respx.post(f"{BASE}/api/v1/invitations/redeem").mock(
        return_value=httpx.Response(
            200,
            json={
                "sealed_ak": sealed_ak,
                "nonce_inv": nonce_inv,
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
                "device_token": "dmage_dtok_join",
                "refresh_token": "dmage_rtok_join",
                "expires_at": "t",
            },
        )
    )
    joiner, recovery = DotMage.join(
        BASE, payload.invitation_id, payload.redeem_secret, "invitee-pw", store=MemoryStore()
    )
    assert joiner.is_unlocked
    assert joiner._session.account_key == account_key  # same AK recovered
    assert recovery is not None


@respx.mock
def test_team_management_and_whoami() -> None:
    client = make_client()
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
    respx.get(f"{BASE}/api/v1/users").mock(
        return_value=httpx.Response(200, json={"users": [], "invitations": []})
    )
    respx.patch(f"{BASE}/api/v1/users/u2").mock(
        return_value=httpx.Response(200, json={"id": "u2", "name": "k", "role": "viewer"})
    )
    respx.delete(f"{BASE}/api/v1/users/u2").mock(
        return_value=httpx.Response(
            200, json={"id": "u2", "name": "k", "devices_revoked": 1, "rotation_required": True}
        )
    )
    assert client.whoami().role == "owner"
    assert client.list_users().users == []
    client.change_role("u2", "viewer")
    assert client.remove_user("u2").rotation_required is True


@respx.mock
def test_audit() -> None:
    client = make_client()
    respx.get(f"{BASE}/api/v1/audit").mock(
        return_value=httpx.Response(
            200,
            json={
                "events": [
                    {
                        "id": "1",
                        "device_id": "d1",
                        "user": "owner",
                        "action": "push",
                        "app_name": "app1",
                        "env_name": "prod",
                        "rev_number": 2,
                        "at": "t",
                    }
                ]
            },
        )
    )
    events = client.audit(app="app1", env="prod", limit=10)
    assert events[0].action == "push"


@respx.mock
def test_change_master_password() -> None:
    creation = keys.create_account_key_material("old-pw", with_recovery=False, **FAST_ARGON)
    keys_body = asdict(creation.material)
    keys_body["key_gen"] = 1
    respx.get(f"{BASE}/api/v1/account/keys").mock(return_value=httpx.Response(200, json=keys_body))
    captured: dict[str, object] = {}

    def patch_handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(200, json={"ok": True})

    respx.patch(f"{BASE}/api/v1/account/keys").mock(side_effect=patch_handler)

    client = make_client()
    client.change_master_password("old-pw", "new-pw")
    # The new wrap uses the default Argon2 parameters and must unwrap with the new password.
    recovered = keys.unwrap_account_key(
        "new-pw",
        salt=captured["salt"],
        nonce_ak=captured["nonce_ak"],
        wrapped_ak=captured["wrapped_ak"],
        argon_memory=suite.DEFAULT_ARGON_MEMORY_KIB,
        argon_iterations=suite.DEFAULT_ARGON_ITERATIONS,
    )
    assert recovered == creation.account_key


@respx.mock
def test_context_manager_closes() -> None:
    with make_client() as client:
        assert client.server_url == BASE
    assert not client.is_unlocked
