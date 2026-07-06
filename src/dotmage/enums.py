"""Enumerations shared across the SDK."""

from __future__ import annotations

from enum import Enum


class MethodEnum(str, Enum):
    """HTTP methods used by the transport layer."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class Role(str, Enum):
    """Team member roles (authorization over ciphertext, not cryptography)."""

    OWNER = "owner"
    EDITOR = "editor"
    VIEWER = "viewer"


class ServerFeature(str, Enum):
    """Optional server features advertised by ``GET /health``."""

    ROTATION = "rotation"
    TEAM = "team"


class DriftState(str, Enum):
    """Result of comparing a local env against the latest remote revision."""

    SYNCED = "synced"
    LOCAL_AHEAD = "local_ahead"
    REMOTE_AHEAD = "remote_ahead"
    DIVERGED = "diverged"
    NO_REMOTE = "no_remote"


class ChangeKind(str, Enum):
    """Per-key classification within a diff."""

    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"
    UNCHANGED = "unchanged"


class AuditAction(str, Enum):
    """Audit-log action identifiers (mirrors ``server/src/enums/audit.py``)."""

    ACCOUNT_INIT = "account.init"
    ACCOUNT_KEYS_UPDATED = "account.keys_updated"
    APP_CREATED = "app.created"
    APP_DELETED = "app.deleted"
    ENV_CREATED = "env.created"
    ENV_DELETED = "env.deleted"
    PUSH = "push"
    PULL = "pull"
    ROLLBACK = "rollback"
    DEVICE_REGISTERED = "device.registered"
    DEVICE_REVOKED = "device.revoked"
    ENROLL_TOKEN_ISSUED = "enroll_token.issued"
    USER_INVITED = "user.invited"
    USER_JOINED = "user.joined"
    USER_ROLE_CHANGED = "user.role_changed"
    USER_REMOVED = "user.removed"
    ROTATE_BEGIN = "rotate.begin"
    ROTATE_BLOB = "rotate.blob"
    ROTATE_COMPLETE = "rotate.complete"
