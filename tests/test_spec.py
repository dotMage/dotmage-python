"""Tests for endpoint request specifications."""

from __future__ import annotations

from dotmage.core.api import spec
from dotmage.enums import MethodEnum


def test_health_is_unauthenticated() -> None:
    s = spec.health()
    assert s.method is MethodEnum.GET
    assert s.path == "/health"
    assert s.auth is False


def test_app_name_with_slashes_is_not_encoded() -> None:
    s = spec.delete_app("work/api")
    assert s.path == "/api/v1/apps/work/api"


def test_env_segment_is_encoded() -> None:
    s = spec.delete_env("work/api", "prod env")
    assert s.path == "/api/v1/apps/work/api/envs/prod%20env"


def test_create_env_copy_from_optional() -> None:
    assert spec.create_env("a", "prod").json == {"name": "prod"}
    assert spec.create_env("a", "prod", copy_from="dev").json == {
        "name": "prod",
        "copy_from": "dev",
    }


def test_push_revision_body() -> None:
    s = spec.push_revision("a", "prod", blob="B", content_hash="H", parent_rev=3)
    assert s.method is MethodEnum.POST
    assert s.path == "/api/v1/apps/a/envs/prod/revisions"
    assert s.json == {"blob": "B", "content_hash": "H", "parent_rev": 3}


def test_auth_device_sends_enroll_bearer() -> None:
    s = spec.auth_device("dmage_etok_x", "laptop")
    assert s.auth is False
    assert s.headers == {"Authorization": "Bearer dmage_etok_x"}
    assert s.json == {"device_name": "laptop"}


def test_audit_params() -> None:
    assert spec.audit().params == {"limit": 100}
    assert spec.audit(app="a", env="prod", limit=10).params == {
        "limit": 10,
        "app": "a",
        "env": "prod",
    }


def test_put_blob_path_and_body() -> None:
    s = spec.put_blob("a", "prod", 5, blob="B", key_gen=2)
    assert s.method is MethodEnum.PUT
    assert s.path == "/api/v1/apps/a/envs/prod/revisions/5/blob"
    assert s.json == {"blob": "B", "key_gen": 2}


def test_redeem_and_complete_are_unauthenticated() -> None:
    assert spec.redeem("i1", "sec").auth is False
    assert spec.complete({"invitation_id": "i1"}).auth is False
