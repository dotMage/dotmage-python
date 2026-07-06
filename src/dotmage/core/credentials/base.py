"""Credential store abstraction."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass


@dataclass
class Credentials:
    """The persisted, non-secret-bearing session state (device tokens, not the account key)."""

    server_url: str | None = None
    device_token: str | None = None
    refresh_token: str | None = None
    device_id: str | None = None
    expires_at: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Credentials:
        fields = {"server_url", "device_token", "refresh_token", "device_id", "expires_at"}
        return cls(**{k: v for k, v in data.items() if k in fields})  # type: ignore[arg-type]


class CredentialStore(ABC):
    """A place to load and persist :class:`Credentials`."""

    @abstractmethod
    def load(self) -> Credentials:
        """Return the stored credentials (an empty :class:`Credentials` if none)."""

    @abstractmethod
    def save(self, credentials: Credentials) -> None:
        """Persist the given credentials."""

    def clear(self) -> None:
        """Remove any stored credentials."""
        self.save(Credentials())
