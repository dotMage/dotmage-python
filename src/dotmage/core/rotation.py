"""Pure helpers for the key-rotation orchestration (shared by both facades)."""

from __future__ import annotations

from typing import Any

from dotmage.core.crypto import keys


def build_begin_body(
    new_gen: int,
    nonce_ak: str,
    wrapped_ak: str,
    new_key: bytes,
    *,
    with_recovery: bool,
) -> tuple[dict[str, Any], str | None]:
    """Build the ``rotate/begin`` request body, optionally adding a recovery wrap.

    Returns the body and the generated recovery code (``None`` when ``with_recovery`` is off).
    """
    body: dict[str, Any] = {
        "new_key_gen": new_gen,
        "nonce_ak": nonce_ak,
        "wrapped_ak": wrapped_ak,
    }
    recovery_code: str | None = None
    if with_recovery:
        recovery_code = keys.generate_recovery_code()
        salt_rc, nonce_rc, wrapped_ak_rc = keys.rewrap_account_key(
            new_key, keys.normalize_recovery_code(recovery_code)
        )
        body.update(salt_rc=salt_rc, nonce_rc=nonce_rc, wrapped_ak_rc=wrapped_ak_rc)
    return body, recovery_code
