"""Client-side cryptography for dotMage.

The dotMage server never sees plaintext. This subpackage implements the full client
contract the reference ``dmage`` CLI uses:

* :mod:`~dotmage.core.crypto.suite` — the frozen algorithm/format contract (one place to
  audit for interoperability).
* :mod:`~dotmage.core.crypto.kdf` — derive a key-encryption key (KEK) from a master
  password via Argon2id.
* :mod:`~dotmage.core.crypto.aead` — authenticated wrap/unwrap and encrypt/decrypt.
* :mod:`~dotmage.core.crypto.keys` — generate and (un)wrap the account key (AK).
* :mod:`~dotmage.core.crypto.blob` — encrypt/decrypt an env dict into the stored ``blob``.
* :mod:`~dotmage.core.crypto.invitation` — seal/open the AK for team invitations.
"""
