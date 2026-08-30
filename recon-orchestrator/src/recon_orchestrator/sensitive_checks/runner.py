"""Runner for sensitive checks: orchestrates the execution of all checks.

This module provides a convenient interface to run all sensitive checks on a
host and collect the results. It's designed to be used by the main recon
orchestrator or other tools that want to perform information disclosure
and misconfiguration scanning.
"""
from __future__ import annotations

from typing import List

from ..config import Settings
from ..models import HostProbe
from .checks import (
    check_sensitive_paths,
    check_cors_misconfiguration,
    check_security_headers,
    check_cookie_flags,
)

async def run_all_checks(
    host: str,
    settings: Settings,
    ports: List[int] | None = None,
) -> List[HostProbe]:
    """Run all sensitive checks and return findings as HostProbe objects.

    This is the main entry point for running sensitive checks. It combines
    path scanning with header/cookie analysis and returns a unified list
    of findings.

    Args:
        host: The target host to check
        settings: Configuration settings for timeouts, rate limits, etc.
        ports: Optional list of ports to check (defaults to [80, 443])

    Returns:
        List of HostProbe objects representing findings
    """
    # Import here to avoid circular imports
    from .checks import run_sensitive_checks
    return await run_sensitive_checks(host, settings, ports)