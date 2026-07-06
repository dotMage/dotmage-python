"""dotMage Python SDK.

A client for the dotMage end-to-end encrypted ``.env`` secret manager. The public API is
re-exported here; import high-level entry points directly::

    from dotmage import DotMage, AsyncDotMage

The server stores only opaque ciphertext, so this package performs all cryptography locally
(see :mod:`dotmage.core.crypto`).
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
