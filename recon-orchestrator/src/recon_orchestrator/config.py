"""Environment-driven config (prefix RECON_). Scope is mandatory to run."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


def _split(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RECON_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- authorized scope (required) --------------------------------------
    target: str | None = None            # primary apex, informational
    in_scope: str = ""                   # comma-separated host / *.wildcard / CIDR
    out_of_scope: str = ""               # comma-separated exclusions
    scope_file: str | None = None        # optional JSON/YAML {in_scope:[], out_of_scope:[]}
    allow_multilevel_wildcard: bool = True

    # --- seeds ------------------------------------------------------------
    seeds: str = ""                      # comma-separated hostnames to probe
    seeds_file: str | None = None        # newline-delimited hostnames

    # --- politeness / transport (NOT evasion) -----------------------------
    requests_per_second: float = 2.0
    max_concurrency: int = 10
    http_timeout: float = 15.0
    connect_timeout: float = 5.0
    max_retries: int = 3
    backoff_base: float = 1.0
    backoff_max: float = 30.0
    user_agent: str = "recon-orchestrator/0.1 (authorized security testing)"
    verify_tls: bool = True

    # --- CVE correlation (optional) --------------------------------------
    cve_index_url: str | None = None     # e.g. http://localhost:8080

    # --- output / logging -------------------------------------------------
    out_file: str | None = None
    log_level: str = "INFO"
    log_json: bool = True
    service_name: str = "recon-orchestrator"

    def in_scope_list(self) -> list[str]:
        return _split(self.in_scope)

    def out_of_scope_list(self) -> list[str]:
        return _split(self.out_of_scope)

    def seed_list(self) -> list[str]:
        return _split(self.seeds)


@lru_cache
def get_settings() -> Settings:
    return Settings()
