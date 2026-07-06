"""dotMage Python SDK.

A client for the dotMage end-to-end encrypted ``.env`` secret manager. Import the high-level
entry points directly::

    from dotmage import DotMage, AsyncDotMage

The server stores only opaque ciphertext, so this package performs all cryptography locally
(see :mod:`dotmage.core.crypto`).
"""

from __future__ import annotations

from dotmage.client import DotMage
from dotmage.core.credentials import Credentials, CredentialStore, FileStore, MemoryStore
from dotmage.exceptions import (
    DecryptionError,
    DotMageAPIError,
    DotMageError,
    MasterPasswordError,
    RevisionConflictError,
    RotationError,
    TeamModeRequiredError,
)
from dotmage.settings import Settings, get_settings

__version__ = "0.1.0"

__all__ = [
    "CredentialStore",
    "Credentials",
    "DecryptionError",
    "DotMage",
    "DotMageAPIError",
    "DotMageError",
    "FileStore",
    "MasterPasswordError",
    "MemoryStore",
    "RevisionConflictError",
    "RotationError",
    "Settings",
    "TeamModeRequiredError",
    "__version__",
    "get_settings",
]
