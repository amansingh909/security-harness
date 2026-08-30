"""Sensitive checks package: checks for information disclosure and misconfigurations.

This module performs GET/HEAD requests on common sensitive paths and checks for
misconfigurations in HTTP headers and cookies. All activity is scoped to
authorized hosts and uses no payloads or injected parameters.
"""
from __future__ import annotations

from .checks import (
    check_sensitive_paths,
    check_cors_misconfiguration,
    check_security_headers,
    check_cookie_flags,
)
from .runner import run_all_checks as run_sensitive_checks

__all__ = [
    "check_sensitive_paths",
    "check_cors_misconfiguration",
    "check_security_headers",
    "check_cookie_flags",
    "run_sensitive_checks",
]