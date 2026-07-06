"""SDK configuration, read from the environment (prefix ``DOTMAGE_``).

Mirrors the ``posthogsdk`` pattern: a ``pydantic-settings`` model plus a cached
:func:`get_settings` accessor. Secrets are held as :class:`~pydantic.SecretStr`.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the dotMage SDK."""

    model_config = SettingsConfigDict(
        env_prefix="DOTMAGE_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    SERVER_URL: str | None = None
    DEVICE_TOKEN: SecretStr | None = None
    REFRESH_TOKEN: SecretStr | None = None
    MASTER_PASSWORD: SecretStr | None = None

    TIMEOUT: float = 10.0
    MAX_RETRIES: int = 5
    LOG_LEVEL: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    """Return a cached :class:`Settings` instance."""
    return Settings()
