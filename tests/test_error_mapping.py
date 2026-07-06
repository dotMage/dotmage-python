"""Tests for mapping server error responses to SDK exceptions."""

from __future__ import annotations

import pytest

from dotmage.exceptions import (
    AuthenticationError,
    BadRequestError,
    DotMageAPIError,
    ForbiddenError,
    NotFoundError,
    RateLimitError,
    RevisionConflictError,
    RotationError,
    TeamModeRequiredError,
    TokenExpiredError,
    error_from_response,
)


def _err(code: str, message: str = "boom") -> dict[str, dict[str, str]]:
    return {"error": {"code": code, "message": message}}


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("TokenExpiredError", TokenExpiredError),
        ("InvalidTokenError", AuthenticationError),
        ("RotationInProgressError", RotationError),
        ("TeamModeRequiredError", TeamModeRequiredError),
        ("DeviceScopeError", ForbiddenError),
        ("BadRevisionError", BadRequestError),
        ("AppNotFoundError", NotFoundError),
        ("RateLimitedError", RateLimitError),
    ],
)
def test_code_mapping(code: str, expected: type[DotMageAPIError]) -> None:
    exc = error_from_response(400, _err(code))
    assert isinstance(exc, expected)
    assert exc.code == code
    assert exc.message == "boom"


def test_revision_conflict_parses_numbers() -> None:
    msg = "Remote is ahead (server rev 7, your parent 5)"
    exc = error_from_response(409, _err("RevisionConflictError", msg))
    assert isinstance(exc, RevisionConflictError)
    assert exc.server_rev == 7
    assert exc.parent_rev == 5


def test_revision_conflict_without_numbers() -> None:
    exc = error_from_response(409, _err("RevisionConflictError", "conflict"))
    assert isinstance(exc, RevisionConflictError)
    assert exc.server_rev is None


def test_unknown_code_uses_status_fallback() -> None:
    exc = error_from_response(403, _err("SomethingNew"))
    assert isinstance(exc, ForbiddenError)


def test_no_error_body_uses_status_fallback() -> None:
    exc = error_from_response(404, {})
    assert isinstance(exc, NotFoundError)
    assert exc.message == "HTTP 404"


def test_fastapi_validation_detail() -> None:
    payload = {"detail": [{"msg": "field required", "loc": ["body", "x"]}]}
    exc = error_from_response(422, payload)
    assert isinstance(exc, DotMageAPIError)
    assert "field required" in exc.message


def test_fastapi_string_detail() -> None:
    exc = error_from_response(400, {"detail": "bad thing"})
    assert exc.message == "bad thing"
