"""File-backed credential store (JSON at a user path, written ``0600``)."""

from __future__ import annotations

import json
import os
from pathlib import Path

from dotmage.core.credentials.base import Credentials, CredentialStore

_DEFAULT_PATH = Path.home() / ".config" / "dotmage" / "credentials.json"


class FileStore(CredentialStore):
    """Persists credentials to a JSON file with owner-only permissions."""

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self.path = Path(path) if path is not None else _DEFAULT_PATH

    def load(self) -> Credentials:
        if not self.path.exists():
            return Credentials()
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return Credentials.from_dict(data)

    def save(self, credentials: Credentials) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(credentials.to_dict(), indent=2)
        # Create/truncate with 0600 so the token file is not world-readable.
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
