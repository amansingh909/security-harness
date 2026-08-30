"""Triage dashboard package.

This package provides utilities to generate human-readable reports from
the nightly runner's JSON output for manual review.
"""
from __future__ import annotations

from .dashboard import generate_dashboard, generate_terminal_report

__all__ = [
    "generate_dashboard",
    "generate_terminal_report",
]