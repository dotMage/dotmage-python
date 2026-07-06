"""Key-rotation flow tests."""

from __future__ import annotations

import json
from dataclasses import asdict

import httpx
import respx
from tests.conftest import BASE, FAST_ARGON, unlocked_client

from dotmage.core.crypto import blob, keys


def _keys_body(password: str = "rot-pw") -> dict[str, object]:
    creation = keys.create_account_key_material(password, with_recovery=False, **FAST_ARGON)
    body = asdict(creation.material)
    body["key_gen"] = 1
    return body


@respx.mock
def test_rotate_reencrypts_stale_and_cuts_over() -> None:
    client, old_key = unlocked_client(key_gen=1)
    stale_blob, stale_hash = blob.encrypt_blob(old_key, {"SECRET": "value"})
    put_captured: dict[str, object] = {}

    respx.get(f"{BASE}/api/v1/account/keys").mock(
        return_value=httpx.Response(200, json=_keys_body())
    )
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
                    "stale": [{"app": "app1", "env": "prod", "rev_number": 1}],
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
    respx.get(f"{BASE}/api/v1/apps/app1/envs/prod/revisions/1").mock(
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

    def put_handler(request: httpx.Request) -> httpx.Response:
        put_captured.update(json.loads(request.content))
        return httpx.Response(200, json={"rev_number": 1, "key_gen": 2})

    respx.put(f"{BASE}/api/v1/apps/app1/envs/prod/revisions/1/blob").mock(side_effect=put_handler)
    respx.post(f"{BASE}/api/v1/account/rotate/complete").mock(
        return_value=httpx.Response(200, json={"current_key_gen": 2})
    )

    seen: list[tuple[int, int]] = []
    recovery = client.rotate("rot-pw", progress=lambda d, t: seen.append((d, t)))

    assert recovery is None
    assert client._session.key_gen == 2
    new_key = client._session.account_key
    assert new_key != old_key
    # The re-encrypted blob is readable with the new key and preserves the plaintext.
    assert blob.decrypt_blob(new_key, put_captured["blob"]) == {"SECRET": "value"}
    assert put_captured["key_gen"] == 2
    assert seen == [(1, 1)]


@respx.mock
def test_rotate_with_recovery_returns_code() -> None:
    client, _ = unlocked_client()
    respx.get(f"{BASE}/api/v1/account/keys").mock(
        return_value=httpx.Response(200, json=_keys_body())
    )
    respx.get(f"{BASE}/api/v1/account/rotate").mock(
        return_value=httpx.Response(
            200, json={"in_progress": False, "current_key_gen": 1, "stale": [], "stale_count": 0}
        )
    )
    respx.post(f"{BASE}/api/v1/account/rotate/begin").mock(
        return_value=httpx.Response(200, json={"new_key_gen": 2, "stale_count": 0})
    )
    respx.post(f"{BASE}/api/v1/account/rotate/complete").mock(
        return_value=httpx.Response(200, json={"current_key_gen": 2})
    )
    recovery = client.rotate("rot-pw", with_recovery=True)
    assert recovery is not None


@respx.mock
def test_rotate_resumes_in_progress() -> None:
    client, _ = unlocked_client()
    keys_body = _keys_body("resume-pw")
    # Pre-existing pending wrap that the resume path must unwrap to recover the new key.
    new_key = keys.generate_account_key()
    nonce_ak, wrapped_ak = keys.wrap_with_salt(
        new_key,
        "resume-pw",
        salt=keys_body["salt"],
        memory_kib=keys_body["argon_memory"],
        iterations=keys_body["argon_iterations"],
    )
    respx.get(f"{BASE}/api/v1/account/keys").mock(return_value=httpx.Response(200, json=keys_body))
    respx.get(f"{BASE}/api/v1/account/rotate").mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "in_progress": True,
                    "current_key_gen": 1,
                    "new_key_gen": 2,
                    "stale_count": 0,
                    "stale": [],
                    "pending_nonce_ak": nonce_ak,
                    "pending_wrapped_ak": wrapped_ak,
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
    respx.post(f"{BASE}/api/v1/account/rotate/complete").mock(
        return_value=httpx.Response(200, json={"current_key_gen": 2})
    )
    client.rotate("resume-pw")
    assert client._session.account_key == new_key
    assert client._session.key_gen == 2
