"""Typed models for dotMage API responses and SDK-level value objects.

Response models parse server payloads (``extra="ignore"`` keeps them forward-compatible). A
few fields differ by endpoint — notably the token-expiry key is ``token_expires_at`` on
init/auth/refresh but ``expires_at`` on ci/enroll/complete — so those use
:class:`~pydantic.AliasChoices`.
"""

from __future__ import annotations

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from dotmage.enums import ChangeKind, DriftState


class _Model(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")


# --------------------------------------------------------------------------- #
# Health & auth
# --------------------------------------------------------------------------- #


class Health(_Model):
    status: str
    version: str
    account_exists: bool
    features: list[str] = Field(default_factory=list)
    server_name: str | None = None


class DeviceCredentials(_Model):
    """Tokens returned by init / device / refresh / ci-token / invitation-complete."""

    device_token: str
    refresh_token: str
    device_id: str
    expires_at: str = Field(validation_alias=AliasChoices("token_expires_at", "expires_at"))


class EnrollToken(_Model):
    token: str
    expires_at: str


# --------------------------------------------------------------------------- #
# Account keys
# --------------------------------------------------------------------------- #


class AccountKeys(_Model):
    salt: str
    argon_memory: int
    argon_iterations: int
    argon_parallelism: int
    argon_version: int
    nonce_ak: str
    wrapped_ak: str
    salt_rc: str | None = None
    nonce_rc: str | None = None
    wrapped_ak_rc: str | None = None
    key_gen: int


# --------------------------------------------------------------------------- #
# Apps, environments, revisions
# --------------------------------------------------------------------------- #


class Environment(_Model):
    id: str
    name: str
    latest_rev: int
    protected: bool
    created_at: str
    updated_at: str


class App(_Model):
    id: str
    name: str
    created_at: str
    updated_at: str
    environments: list[Environment] = Field(default_factory=list)


class RevisionMeta(_Model):
    rev_number: int
    content_hash: str | None = None
    created_at: str
    device_id: str
    rollback_of: int | None = None


class Revision(_Model):
    rev_number: int
    blob: str
    content_hash: str | None = None
    created_at: str
    device_id: str
    parent_rev: int | None = None
    rollback_of: int | None = None
    key_gen: int


class PushResult(_Model):
    rev_number: int
    created_at: str
    device_id: str


class RollbackResult(_Model):
    rev_number: int
    copied_from: int


# --------------------------------------------------------------------------- #
# Devices
# --------------------------------------------------------------------------- #


class DeviceInfo(_Model):
    id: str
    name: str
    last_seen: str | None = None
    expires_at: str
    revoked: bool
    created_at: str
    allowed_app: str | None = None
    allowed_env: str | None = None


# --------------------------------------------------------------------------- #
# Team
# --------------------------------------------------------------------------- #


class WhoAmI(_Model):
    user_id: str | None = None
    name: str
    role: str
    device_id: str
    device_name: str


class TeamUser(_Model):
    id: str
    name: str
    role: str
    status: str
    key_gen: int
    created_at: str


class TeamInvitationInfo(_Model):
    id: str
    name: str
    role: str
    status: str
    expires_at: str


class Team(_Model):
    users: list[TeamUser] = Field(default_factory=list)
    invitations: list[TeamInvitationInfo] = Field(default_factory=list)


class ArgonDefaults(_Model):
    memory: int
    iterations: int
    parallelism: int
    version: int


class RedeemResponse(_Model):
    sealed_ak: str
    nonce_inv: str
    key_gen: int
    name: str
    role: str
    argon_defaults: ArgonDefaults


class InviteResult(_Model):
    invitation_id: str
    expires_at: str


class RemoveResult(_Model):
    id: str
    name: str
    devices_revoked: int
    rotation_required: bool


# --------------------------------------------------------------------------- #
# Rotation & audit
# --------------------------------------------------------------------------- #


class StaleRevision(_Model):
    app: str
    env: str
    rev_number: int


class RotationStatus(_Model):
    in_progress: bool
    current_key_gen: int
    new_key_gen: int | None = None
    stale_count: int | None = None
    stale: list[StaleRevision] = Field(default_factory=list)
    pending_nonce_ak: str | None = None
    pending_wrapped_ak: str | None = None


class RotateBeginResult(_Model):
    new_key_gen: int
    stale_count: int


class AuditEvent(_Model):
    id: str
    device_id: str | None = None
    user: str | None = None
    action: str
    app_name: str | None = None
    env_name: str | None = None
    rev_number: int | None = None
    at: str


# --------------------------------------------------------------------------- #
# SDK value objects (produced locally, not raw server payloads)
# --------------------------------------------------------------------------- #


class InvitePayload(_Model):
    """The shareable half of an invitation — hand this to the invitee out of band."""

    invitation_id: str
    redeem_secret: str
    name: str
    role: str
    expires_at: str


class KeyChange(_Model):
    key: str
    kind: ChangeKind
    old: str | None = None
    new: str | None = None


class Diff(_Model):
    app: str
    env: str
    rev_a: int
    rev_b: int
    changes: list[KeyChange] = Field(default_factory=list)

    @property
    def added(self) -> list[KeyChange]:
        return [c for c in self.changes if c.kind is ChangeKind.ADDED]

    @property
    def removed(self) -> list[KeyChange]:
        return [c for c in self.changes if c.kind is ChangeKind.REMOVED]

    @property
    def changed(self) -> list[KeyChange]:
        return [c for c in self.changes if c.kind is ChangeKind.CHANGED]

    def pretty(self) -> str:
        """Render a compact, human-readable diff (unchanged keys omitted)."""
        symbol = {
            ChangeKind.ADDED: "+",
            ChangeKind.REMOVED: "-",
            ChangeKind.CHANGED: "~",
            ChangeKind.UNCHANGED: " ",
        }
        lines = [f"{self.app}:{self.env}  rev {self.rev_a} -> rev {self.rev_b}"]
        for c in self.changes:
            if c.kind is ChangeKind.UNCHANGED:
                continue
            lines.append(f"  {symbol[c.kind]} {c.key}")
        return "\n".join(lines)


class DriftStatus(_Model):
    app: str
    env: str
    state: DriftState
    local_hash: str | None = None
    remote_hash: str | None = None
    remote_rev: int = 0
