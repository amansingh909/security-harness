"""Environment-driven config (prefix RPT_)."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RPT_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )
    # Optional enrichment against a running cve-index API.
    cve_index_url: str | None = None
    http_timeout: float = 15.0
    log_level: str = "INFO"
    log_json: bool = True
    service_name: str = "bounty-reporter"


@lru_cache
def get_settings() -> Settings:
    return Settings()
