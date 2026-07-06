"""In-memory credential store (the default; nothing is written to disk)."""

from __future__ import annotations

from dotmage.core.credentials.base import Credentials, CredentialStore


class MemoryStore(CredentialStore):
    """Holds credentials in process memory only."""

    def __init__(self, credentials: Credentials | None = None) -> None:
        self._credentials = credentials or Credentials()

    def load(self) -> Credentials:
        return self._credentials

    def save(self, credentials: Credentials) -> None:
        self._credentials = credentials
