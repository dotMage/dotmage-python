"""Exception hierarchy for the dotMage SDK.

Two families live here:

* **API errors** (:class:`DotMageAPIError` and subclasses) mirror the domain errors returned
  by the server. The server serialises every domain error as
  ``{"error": {"code": "<ClassName>", "message": "..."}}`` with a matching HTTP status
  (see ``server/src/core/auth/exceptions.py``). :func:`error_from_response` maps that
  ``code`` back onto the right SDK class.
* **Client errors** (:class:`CryptoError` and subclasses, :class:`ConfigError`) are raised
  locally — most importantly when decryption fails because the master password is wrong.
"""

from __future__ import annotations

from typing import Any


class DotMageError(Exception):
    """Base class for every error raised by the SDK."""

    def __init__(self, message: str = "dotMage error") -> None:
        super().__init__(message)
        self.message = message


# --------------------------------------------------------------------------- #
# API errors (raised from server responses)
# --------------------------------------------------------------------------- #


class DotMageAPIError(DotMageError):
    """An error returned by the dotMage server.

    Attributes:
        status_code: HTTP status code of the response.
        code: The server-side error code (the exception class name), if present.
        payload: The raw decoded JSON body, when available.
    """

    def __init__(
        self,
        message: str = "dotMage API error",
        *,
        status_code: int | None = None,
        code: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.payload = payload or {}


class AuthenticationError(DotMageAPIError):
    """Missing, invalid, or revoked credentials (HTTP 401)."""


class TokenExpiredError(AuthenticationError):
    """The device token has expired; a refresh should be attempted."""


class DeviceRevokedError(AuthenticationError):
    """The device (or its enrollment token) has been revoked."""


class EnrollmentError(AuthenticationError):
    """An enrollment token was missing, invalid, revoked, or expired."""


class BootstrapError(DotMageAPIError):
    """The bootstrap secret was rejected (HTTP 403)."""


class AccountStateError(DotMageAPIError):
    """The account is in the wrong state (already initialised / not initialised)."""


class ForbiddenError(DotMageAPIError):
    """The caller's role or token scope does not permit the action (HTTP 403)."""


class NotFoundError(DotMageAPIError):
    """A requested app, environment, revision, device, or user was not found (HTTP 404)."""


class BadRequestError(DotMageAPIError):
    """The request was malformed, e.g. a bad revision selector (HTTP 400)."""


class RevisionConflictError(DotMageAPIError):
    """A push was rejected because the remote is ahead (HTTP 409).

    Attributes:
        server_rev: The latest revision number the server currently holds.
        parent_rev: The parent revision the client based its push on.
    """

    def __init__(
        self,
        message: str = "Remote is ahead",
        *,
        server_rev: int | None = None,
        parent_rev: int | None = None,
        status_code: int | None = None,
        code: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, status_code=status_code, code=code, payload=payload)
        self.server_rev = server_rev
        self.parent_rev = parent_rev


class RotationError(DotMageAPIError):
    """A key-rotation precondition failed (in progress, incomplete, not active, conflict)."""


class TeamModeRequiredError(DotMageAPIError):
    """A team-only endpoint was called on a solo server (HTTP 404 with a team code)."""


class TeamError(DotMageAPIError):
    """A team management error (bad invitation, user exists, last owner, ...)."""


class RateLimitError(DotMageAPIError):
    """Too many requests (HTTP 429)."""


# --------------------------------------------------------------------------- #
# Client-side errors
# --------------------------------------------------------------------------- #


class CryptoError(DotMageError):
    """Base class for local cryptographic failures."""


class DecryptionError(CryptoError):
    """Authenticated decryption failed (wrong key, tampered ciphertext, or bad format)."""


class MasterPasswordError(DecryptionError):
    """The master password (or recovery code) could not unwrap the account key."""


class ContentIntegrityError(CryptoError):
    """A decrypted blob did not match its expected ``content_hash``."""


class InteropError(CryptoError):
    """A ciphertext/envelope used a version or format this SDK does not understand."""


class ConfigError(DotMageError):
    """The SDK was misconfigured or used in an invalid state (e.g. locked session)."""


class LockedError(ConfigError):
    """An operation needed the account key but the session is locked."""


# --------------------------------------------------------------------------- #
# Mapping server error codes -> SDK exception classes
# --------------------------------------------------------------------------- #

_CODE_MAP: dict[str, type[DotMageAPIError]] = {
    # Auth
    "NotAuthenticatedError": AuthenticationError,
    "InvalidTokenError": AuthenticationError,
    "UnauthorizedError": AuthenticationError,
    "DeviceRevokedError": DeviceRevokedError,
    "TokenExpiredError": TokenExpiredError,
    "EnrollmentTokenRequiredError": EnrollmentError,
    "InvalidEnrollmentTokenError": EnrollmentError,
    "EnrollmentTokenRevokedError": EnrollmentError,
    "EnrollmentTokenExpiredError": EnrollmentError,
    "InvalidRefreshTokenError": AuthenticationError,
    # Account / bootstrap
    "AccountExistsError": AccountStateError,
    "AccountNotFoundError": AccountStateError,
    "InvalidBootstrapError": BootstrapError,
    # Apps / envs / revisions
    "AppExistsError": TeamError,
    "AppNotFoundError": NotFoundError,
    "EnvExistsError": TeamError,
    "EnvNotFoundError": NotFoundError,
    "SourceEnvNotFoundError": NotFoundError,
    "AppOrEnvNotFoundError": NotFoundError,
    "RevisionNotFoundError": NotFoundError,
    "BadRevisionError": BadRequestError,
    "RevisionConflictError": RevisionConflictError,
    # Rotation
    "RotationInProgressError": RotationError,
    "RotationConflictError": RotationError,
    "RotationNotActiveError": RotationError,
    "RotationIncompleteError": RotationError,
    # Devices
    "DeviceNotFoundError": NotFoundError,
    "DeviceScopeError": ForbiddenError,
    # Team / roles
    "TeamModeRequiredError": TeamModeRequiredError,
    "NotAnOwnerError": ForbiddenError,
    "RoleForbiddenError": ForbiddenError,
    "UserExistsError": TeamError,
    "InvitationInvalidError": TeamError,
    "UserNotFoundError": NotFoundError,
    "LastOwnerError": TeamError,
    # Rate limit
    "RateLimitedError": RateLimitError,
}


def _status_fallback(status_code: int) -> type[DotMageAPIError]:
    return {
        400: BadRequestError,
        401: AuthenticationError,
        403: ForbiddenError,
        404: NotFoundError,
        409: DotMageAPIError,
        429: RateLimitError,
    }.get(status_code, DotMageAPIError)


def error_from_response(
    status_code: int,
    payload: dict[str, Any] | None,
) -> DotMageAPIError:
    """Build the appropriate :class:`DotMageAPIError` from a server error response.

    Args:
        status_code: HTTP status code of the response.
        payload: Decoded JSON body. Expected shape ``{"error": {"code", "message"}}``;
            FastAPI validation errors (``{"detail": ...}``) are tolerated too.

    Returns:
        A concrete :class:`DotMageAPIError` subclass populated with code, message and status.
    """
    payload = payload or {}
    raw_error = payload.get("error")
    error: dict[str, Any] = raw_error if isinstance(raw_error, dict) else {}
    code = error.get("code")
    message = error.get("message") or _detail_message(payload) or f"HTTP {status_code}"

    cls = _CODE_MAP.get(code) if code else None
    if cls is None:
        cls = _status_fallback(status_code)

    if cls is RevisionConflictError:
        server_rev, parent_rev = _parse_conflict(message)
        return RevisionConflictError(
            message,
            server_rev=server_rev,
            parent_rev=parent_rev,
            status_code=status_code,
            code=code,
            payload=payload,
        )

    return cls(message, status_code=status_code, code=code, payload=payload)


def _detail_message(payload: dict[str, Any]) -> str | None:
    detail = payload.get("detail")
    if isinstance(detail, str):
        return detail
    if isinstance(detail, list) and detail:
        return "; ".join(str(item.get("msg", item)) for item in detail if isinstance(item, dict))
    return None


def _parse_conflict(message: str) -> tuple[int | None, int | None]:
    """Best-effort extraction of the two revision numbers from the conflict message."""
    import re

    nums = re.findall(r"\d+", message)
    if len(nums) >= 2:
        return int(nums[0]), int(nums[1])
    return None, None
