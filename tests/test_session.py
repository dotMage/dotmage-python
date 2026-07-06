"""Tests for the in-memory session."""

from __future__ import annotations

import pytest

from dotmage.core.crypto import keys
from dotmage.exceptions import LockedError
from dotmage.session import Session


def test_locked_session_raises() -> None:
    session = Session()
    assert session.is_unlocked is False
    with pytest.raises(LockedError):
        _ = session.account_key
    with pytest.raises(LockedError):
        _ = session.key_gen


def test_unlock_encrypt_decrypt_roundtrip() -> None:
    session = Session()
    session.set_key(keys.generate_account_key(), key_gen=1)
    assert session.is_unlocked
    assert session.key_gen == 1

    ciphertext, digest = session.encrypt({"A": "1"})
    assert session.decrypt(ciphertext) == {"A": "1"}
    assert len(digest) == 64


def test_clear_locks_session() -> None:
    session = Session()
    session.set_key(b"k" * 32, key_gen=2)
    session.clear()
    assert not session.is_unlocked
    with pytest.raises(LockedError):
        _ = session.account_key
