"""HackerOne scope import package.

Turns a program's structured scopes — from the API or a hand-exported JSON
file — into the in-scope/out-of-scope host patterns ScopeGuard expects.
"""
from __future__ import annotations

from .scope_import import (
    HOST_ASSET_TYPES,
    HackerOneAsset,
    fetch_structured_scopes,
    parse_hackerone_scope,
    parse_structured_scopes,
    to_host_pattern,
)

__all__ = [
    "HOST_ASSET_TYPES",
    "HackerOneAsset",
    "fetch_structured_scopes",
    "parse_hackerone_scope",
    "parse_structured_scopes",
    "to_host_pattern",
]
