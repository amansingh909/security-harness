"""Passive subdomain enumeration package.

crt.sh is the primary source today. Module 1 injects additional hosts into the
recon pipeline for follow-up passes without changing any core scope-gating.
"""
from __future__ import annotations

from .fetch_crtsh import fetch_crtsh_for_apex

__all__ = ["fetch_crtsh_for_apex"]