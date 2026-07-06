"""Tests for response models and SDK value objects."""

from __future__ import annotations

from dotmage.enums import ChangeKind, DriftState
from dotmage.models import (
    App,
    DeviceCredentials,
    Diff,
    DriftStatus,
    Health,
    KeyChange,
    RotationStatus,
)


def test_device_credentials_accepts_token_expires_at() -> None:
    creds = DeviceCredentials.model_validate(
        {
            "device_token": "dmage_dtok_x",
            "refresh_token": "dmage_rtok_y",
            "device_id": "d1",
            "token_expires_at": "2026-07-06T00:00:00Z",
        }
    )
    assert creds.expires_at == "2026-07-06T00:00:00Z"


def test_device_credentials_accepts_expires_at() -> None:
    creds = DeviceCredentials.model_validate(
        {
            "device_token": "dmage_dtok_x",
            "refresh_token": "dmage_rtok_y",
            "device_id": "d1",
            "expires_at": "2026-07-06T00:00:00Z",
        }
    )
    assert creds.expires_at == "2026-07-06T00:00:00Z"


def test_app_nests_environments() -> None:
    app = App.model_validate(
        {
            "id": "a1",
            "name": "work/api",
            "created_at": "t",
            "updated_at": "t",
            "environments": [
                {
                    "id": "e1",
                    "name": "prod",
                    "latest_rev": 3,
                    "protected": False,
                    "created_at": "t",
                    "updated_at": "t",
                }
            ],
        }
    )
    assert app.name == "work/api"
    assert app.environments[0].latest_rev == 3


def test_health_ignores_unknown_fields() -> None:
    health = Health.model_validate(
        {"status": "ok", "version": "0.2.0", "account_exists": True, "extra": "ignored"}
    )
    assert health.features == []


def test_rotation_status_minimal() -> None:
    status = RotationStatus.model_validate({"in_progress": False, "current_key_gen": 1})
    assert status.new_key_gen is None
    assert status.stale == []


def test_diff_helpers_and_pretty() -> None:
    diff = Diff(
        app="work/api",
        env="prod",
        rev_a=1,
        rev_b=2,
        changes=[
            KeyChange(key="NEW", kind=ChangeKind.ADDED, new="1"),
            KeyChange(key="GONE", kind=ChangeKind.REMOVED, old="x"),
            KeyChange(key="MOD", kind=ChangeKind.CHANGED, old="a", new="b"),
            KeyChange(key="SAME", kind=ChangeKind.UNCHANGED, old="z", new="z"),
        ],
    )
    assert [c.key for c in diff.added] == ["NEW"]
    assert [c.key for c in diff.removed] == ["GONE"]
    assert [c.key for c in diff.changed] == ["MOD"]
    rendered = diff.pretty()
    assert "+ NEW" in rendered
    assert "- GONE" in rendered
    assert "~ MOD" in rendered
    assert "SAME" not in rendered


def test_drift_status() -> None:
    drift = DriftStatus(app="a", env="e", state=DriftState.SYNCED, remote_rev=5)
    assert drift.state is DriftState.SYNCED
    assert drift.remote_rev == 5
