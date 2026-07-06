"""Direct tests for the pure diff/drift helpers."""

from __future__ import annotations

from dotmage.core.diffing import compute_diff, compute_drift
from dotmage.enums import ChangeKind, DriftState


def test_compute_diff_all_kinds() -> None:
    diff = compute_diff(
        "a",
        "e",
        1,
        2,
        {"SAME": "x", "MOD": "1", "GONE": "y"},
        {"SAME": "x", "MOD": "2", "NEW": "z"},
    )
    kinds = {c.key: c.kind for c in diff.changes}
    assert kinds["SAME"] is ChangeKind.UNCHANGED
    assert kinds["MOD"] is ChangeKind.CHANGED
    assert kinds["GONE"] is ChangeKind.REMOVED
    assert kinds["NEW"] is ChangeKind.ADDED


def test_compute_drift_states() -> None:
    assert compute_drift("a", "e", {"A": "1"}, None, 0).state is DriftState.NO_REMOTE
    from dotmage.core.crypto import blob

    h = blob.content_hash({"A": "1"})
    assert compute_drift("a", "e", {"A": "1"}, h, 3).state is DriftState.SYNCED
    assert compute_drift("a", "e", {"A": "2"}, h, 3).state is DriftState.DIVERGED
