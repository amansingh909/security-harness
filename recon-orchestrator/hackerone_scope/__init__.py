"""HackerOne scope import package.

This package provides utilities to import and parse HackerOne scope data
for use with the recon-orchestrator's ScopeGuard.
"""
from __future__ import annotations

from .scope_import import parse_hackerone_scope

__all__ = [
    "parse_hackerone_scope",
]