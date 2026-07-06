"""Pure diff/drift computation shared by the sync and async facades."""

from __future__ import annotations

from dotmage.core.crypto import blob
from dotmage.enums import ChangeKind, DriftState
from dotmage.models import Diff, DriftStatus, KeyChange


def compute_diff(
    app: str,
    env: str,
    rev_a: int,
    rev_b: int,
    data_a: dict[str, str],
    data_b: dict[str, str],
) -> Diff:
    """Compute a per-key diff going from ``rev_a`` (``data_a``) to ``rev_b`` (``data_b``)."""
    changes: list[KeyChange] = []
    for key in sorted(set(data_a) | set(data_b)):
        in_a, in_b = key in data_a, key in data_b
        if in_a and not in_b:
            changes.append(KeyChange(key=key, kind=ChangeKind.REMOVED, old=data_a[key]))
        elif in_b and not in_a:
            changes.append(KeyChange(key=key, kind=ChangeKind.ADDED, new=data_b[key]))
        elif data_a[key] != data_b[key]:
            changes.append(
                KeyChange(key=key, kind=ChangeKind.CHANGED, old=data_a[key], new=data_b[key])
            )
        else:
            changes.append(
                KeyChange(key=key, kind=ChangeKind.UNCHANGED, old=data_a[key], new=data_b[key])
            )
    return Diff(app=app, env=env, rev_a=rev_a, rev_b=rev_b, changes=changes)


def compute_drift(
    app: str,
    env: str,
    local: dict[str, str],
    remote_hash: str | None,
    remote_rev: int,
) -> DriftStatus:
    """Classify a local env against the latest remote revision (hash comparison)."""
    local_hash = blob.content_hash(local)
    if remote_rev == 0:
        state = DriftState.NO_REMOTE
    elif remote_hash is not None and remote_hash == local_hash:
        state = DriftState.SYNCED
    else:
        state = DriftState.DIVERGED
    return DriftStatus(
        app=app,
        env=env,
        state=state,
        local_hash=local_hash,
        remote_hash=remote_hash,
        remote_rev=remote_rev,
    )
