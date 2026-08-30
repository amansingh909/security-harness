"""Tech detection package: port sweeping and stack fingerprinting.

This module performs lightweight, GET/HEAD-based port sweeps beyond the standard
web ports and attempts to identify technologies in use from response headers
and HTML content. All activity is scoped to authorized hosts and uses no
payloads or injected parameters.
"""
from __future__ import annotations

from .port_sweep import TechProber, sweep_ports
from .tech_fingerprint import (
    detect_tech_from_headers,
    detect_tech_from_html,
    detect_tech_from_probe,
    enhance_probe_with_tech,
)

__all__ = [
    "TechProber",
    "sweep_ports",
    "detect_tech_from_headers",
    "detect_tech_from_html",
    "detect_tech_from_probe",
    "enhance_probe_with_tech",
]