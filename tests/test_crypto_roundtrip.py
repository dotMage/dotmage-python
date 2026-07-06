"""Round-trip and failure-mode tests for the crypto core."""

from __future__ import annotations

import pytest

from dotmage.core.crypto import aead, invitation, keys
from dotmage.core.crypto.kdf import derive_kek
from dotmage.exceptions import DecryptionError, MasterPasswordError

FAST = {"memory_kib": 8192, "iterations": 2}


def test_kdf_is_deterministic() -> None:
    salt = bytes(range(16))
    a = derive_kek("pw", salt, **FAST)
    b = derive_kek("pw", salt, **FAST)
    assert a == b == a  # stable
    assert derive_kek("other", salt, **FAST) != a


def test_kdf_rejects_bad_salt_length() -> None:
    with pytest.raises(ValueError, match="salt must be"):
        derive_kek("pw", b"short", **FAST)


def test_aead_tamper_is_rejected() -> None:
    key = keys.generate_account_key()
    nonce, ct = aead.encrypt(key, b"secret")
    tampered = bytes([ct[0] ^ 0x01]) + ct[1:]
    with pytest.raises(DecryptionError):
        aead.decrypt(key, nonce, tampered)


def test_account_key_wrap_unwrap_with_password() -> None:
    creation = keys.create_account_key_material("master-pw", with_recovery=False, **FAST)
    m = creation.material
    recovered = keys.unwrap_account_key(
        "master-pw",
        salt=m.salt,
        nonce_ak=m.nonce_ak,
        wrapped_ak=m.wrapped_ak,
        argon_memory=m.argon_memory,
        argon_iterations=m.argon_iterations,
    )
    assert recovered == creation.account_key
    assert creation.recovery_code is None
    assert m.salt_rc is None


def test_account_key_wrong_password_raises() -> None:
    creation = keys.create_account_key_material("master-pw", with_recovery=False, **FAST)
    m = creation.material
    with pytest.raises(MasterPasswordError):
        keys.unwrap_account_key(
            "wrong",
            salt=m.salt,
            nonce_ak=m.nonce_ak,
            wrapped_ak=m.wrapped_ak,
            argon_memory=m.argon_memory,
            argon_iterations=m.argon_iterations,
        )


def test_recovery_code_unwraps_the_same_key() -> None:
    creation = keys.create_account_key_material("master-pw", with_recovery=True, **FAST)
    m = creation.material
    assert creation.recovery_code is not None
    recovered = keys.unwrap_account_key_with_recovery(
        creation.recovery_code,
        salt_rc=m.salt_rc,
        nonce_rc=m.nonce_rc,
        wrapped_ak_rc=m.wrapped_ak_rc,
        argon_memory=m.argon_memory,
        argon_iterations=m.argon_iterations,
    )
    assert recovered == creation.account_key


def test_recovery_code_normalisation() -> None:
    creation = keys.create_account_key_material("pw", with_recovery=True, **FAST)
    m = creation.material
    assert creation.recovery_code is not None
    messy = f"  {creation.recovery_code.lower()}  "
    recovered = keys.unwrap_account_key_with_recovery(
        messy,
        salt_rc=m.salt_rc,
        nonce_rc=m.nonce_rc,
        wrapped_ak_rc=m.wrapped_ak_rc,
        argon_memory=m.argon_memory,
        argon_iterations=m.argon_iterations,
    )
    assert recovered == creation.account_key


def test_recovery_unwrap_without_wrap_configured() -> None:
    with pytest.raises(MasterPasswordError, match="no recovery wrap"):
        keys.unwrap_account_key_with_recovery(
            "ANY-CODE",
            salt_rc=None,
            nonce_rc=None,
            wrapped_ak_rc=None,
            argon_memory=8192,
            argon_iterations=2,
        )


def test_rewrap_preserves_key() -> None:
    ak = keys.generate_account_key()
    salt, nonce, wrapped = keys.rewrap_account_key(ak, "new-pw", **FAST)
    recovered = keys.unwrap_account_key(
        "new-pw",
        salt=salt,
        nonce_ak=nonce,
        wrapped_ak=wrapped,
        argon_memory=8192,
        argon_iterations=2,
    )
    assert recovered == ak


def test_invitation_seal_open_roundtrip() -> None:
    ak = keys.generate_account_key()
    secret = invitation.generate_redeem_secret()
    nonce_inv, sealed = invitation.seal_account_key(ak, secret)
    assert invitation.open_account_key(sealed, nonce_inv, secret) == ak


def test_invitation_wrong_secret_rejected() -> None:
    ak = keys.generate_account_key()
    nonce_inv, sealed = invitation.seal_account_key(ak, "right-secret")
    with pytest.raises(DecryptionError):
        invitation.open_account_key(sealed, nonce_inv, "wrong-secret")
