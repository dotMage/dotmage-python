"""Tests for blob encryption/decryption and content hashing."""

from __future__ import annotations

import pytest

from dotmage.core.crypto import blob, keys
from dotmage.exceptions import ContentIntegrityError, DecryptionError, InteropError


def test_blob_roundtrip() -> None:
    ak = keys.generate_account_key()
    data = {"DATABASE_URL": "postgres://u:p@h/db", "UNICODE": "ключ=значение 🔐"}
    envelope, digest = blob.encrypt_blob(ak, data)
    assert blob.decrypt_blob(ak, envelope) == data
    assert digest == blob.content_hash(data)


def test_blob_is_nondeterministic_but_hash_is_stable() -> None:
    ak = keys.generate_account_key()
    data = {"A": "1"}
    first, h1 = blob.encrypt_blob(ak, data)
    second, h2 = blob.encrypt_blob(ak, data)
    assert first != second  # random nonce per encryption
    assert h1 == h2  # content hash depends only on plaintext


def test_blob_wrong_key_fails() -> None:
    envelope, _ = blob.encrypt_blob(keys.generate_account_key(), {"A": "1"})
    with pytest.raises(DecryptionError):
        blob.decrypt_blob(keys.generate_account_key(), envelope)


def test_blob_bad_version_raises_interop() -> None:
    ak = keys.generate_account_key()
    envelope, _ = blob.encrypt_blob(ak, {"A": "1"})
    from dotmage.core.crypto import suite

    raw = bytearray(suite.b64decode(envelope))
    raw[0] = 99  # unknown version
    with pytest.raises(InteropError, match="unsupported blob version"):
        blob.decrypt_blob(ak, suite.b64encode(bytes(raw)))


def test_blob_too_short_raises_interop() -> None:
    from dotmage.core.crypto import suite

    with pytest.raises(InteropError, match="too short"):
        blob.decrypt_blob(keys.generate_account_key(), suite.b64encode(b"\x01"))


def test_verify_content_hash() -> None:
    data = {"A": "1"}
    blob.verify_content_hash(data, blob.content_hash(data))  # ok
    blob.verify_content_hash(data, None)  # None passes
    with pytest.raises(ContentIntegrityError):
        blob.verify_content_hash(data, "deadbeef")
