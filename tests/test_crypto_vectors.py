"""Frozen cryptographic vectors — guard the on-the-wire format against regressions.

These use fixed inputs (salt, nonce, key) so the outputs are deterministic. They are the
contract this SDK commits to; aligning them with the reference ``dmage`` client is the
interop step tracked in ``docs/crypto.md``.
"""

from __future__ import annotations

from dotmage.core.crypto import aead, blob, invitation, suite
from dotmage.core.crypto.kdf import derive_kek

KEK_HEX = "a891dd91a3d123add6ea78ceedcc94a7f1dc1e4ca480e57e6f240a113662ea2f"
AEAD_CT_B64 = "NIijrUrj1Un2VCAN3p9UR+Qvf5pQcVaDcBlzj88="
CONTENT_HASH = "3eda2f06741f1d082a60e34bf134dace8b60136ae69b552a2137bd898f27ea85"
SEAL_KEY_HEX = "087e5923948532d0f74c3d9f814829bc3e87605db2fa1d7256aff53e23f33a3b"
REDEEM_HASH = "d3046ecc8dd3242adf62801a33ef1004003b01b4c8f558df72e637da30321ccd"


def test_kdf_vector() -> None:
    salt = bytes(range(16))
    kek = derive_kek("correct horse battery staple", salt, memory_kib=8192, iterations=2)
    assert kek.hex() == KEK_HEX


def test_aead_vector_roundtrips() -> None:
    key = bytes([7]) * 32
    nonce = bytes([9]) * 24
    used_nonce, ciphertext = aead.encrypt(key, b"hello dotmage", nonce=nonce)
    assert used_nonce == nonce
    assert suite.b64encode(ciphertext) == AEAD_CT_B64
    assert aead.decrypt(key, nonce, ciphertext) == b"hello dotmage"


def test_content_hash_is_order_independent() -> None:
    assert blob.content_hash({"B": "2", "A": "1"}) == CONTENT_HASH
    assert blob.content_hash({"A": "1", "B": "2"}) == CONTENT_HASH


def test_invitation_seal_key_is_domain_separated() -> None:
    seal_key = invitation._seal_key("shared-secret")
    assert seal_key.hex() == SEAL_KEY_HEX
    assert invitation.redeem_hash("shared-secret") == REDEEM_HASH
    # The seal key the server can never reconstruct from the redeem_hash it stores.
    assert seal_key.hex() != REDEEM_HASH
