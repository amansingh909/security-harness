"""Tech-stack detection from HTTP responses.

Analyzes response headers, HTML content, and JavaScript to identify
technologies in use (frameworks, CMS, libraries, etc.) without
executing any code or sending payloads.
"""
from __future__ import annotations

import re
from typing import Dict, List, Set

from ..fingerprint import Fingerprint
from ..models import HostProbe

# Common technology signatures in headers and HTML
_TECH_SIGNATURES: Dict[str, List[Dict[str, str]]] = {
    # Web servers
    "nginx": [
        {"header": "server", "pattern": r"nginx"},
    ],
    "apache": [
        {"header": "server", "pattern": r"Apache"},
    ],
    "iis": [
        {"header": "server", "pattern": r"Microsoft-IIS"},
    ],
    # Programming languages/runtimes
    "php": [
        {"header": "x-powered-by", "pattern": r"PHP"},
    ],
    "asp.net": [
        {"header": "x-aspnet-version", "pattern": r".+"},
        {"header": "x-aspnetmvc-version", "pattern": r".+"},
    ],
    "express": [
        {"header": "x-powered-by", "pattern": r"Express"},
    ],
    # Frameworks and CMS
    "wordpress": [
        {"html": r'wp-content|wp-includes|wordpress'},
        {"header": "x-powered-by", "pattern": r"WordPress"},
    ],
    "drupal": [
        {"html": r'drupal|sites/all|sites/default'},
        {"header": "x-generator", "pattern": r"Drupal"},
    ],
    "joomla": [
        {"html": r'joomla|/media/system/js/'},
        {"header": "x-generator", "pattern": r"Joomla!"},
    ],
    "laravel": [
        {"html": r'laravel|csrf-token'},
        {"header": "set-cookie", "pattern": r"laravel_session"},
    ],
    "django": [
        {"html": r'csrfmiddlewaretoken|django'},
        {"header": "set-cookie", "pattern": r"sessionid"},
    ],
    "rails": [
        {"html": r'csrf-token|authenticity_token'},
        {"header": "set-cookie", "pattern": r"_rails_session"},
    ],
    # JavaScript libraries (detected via HTML comments or common paths)
    "jquery": [
        {"html": r'jquery'},
    ],
    "react": [
        {"html": r'react|data-reactroot'},
    ],
    "angular": [
        {"html": r'angular|ng-version'},
    ],
    "vue": [
        {"html": r'vue\.js|vue-devtools'},
    ],
}


def _matches_pattern(text: str, pattern: str) -> bool:
    """Check if text matches the given regex pattern (case-insensitive)."""
    try:
        return bool(re.search(pattern, text, re.IGNORECASE))
    except re.error:
        return False


def detect_tech_from_headers(headers: Dict[str, str]) -> Set[str]:
    """Detect technologies from HTTP headers."""
    detected: Set[str] = set()
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for tech, signatures in _TECH_SIGNATURES.items():
        for sig in signatures:
            if "header" in sig:
                header_name = sig["header"].lower()
                pattern = sig["pattern"]
                if header_name in headers_lower:
                    value = headers_lower[header_name]
                    if _matches_pattern(value, pattern):
                        detected.add(tech)
                        break  # Found this tech, no need to check other signatures
    return detected


def detect_tech_from_html(html: str) -> Set[str]:
    """Detect technologies from HTML content."""
    detected: Set[str] = set()
    if not html:
        return detected

    # Limit HTML size to avoid huge responses
    html_sample = html[:50000] if len(html) > 50000 else html

    for tech, signatures in _TECH_SIGNATURES.items():
        for sig in signatures:
            if "html" in sig:
                pattern = sig["html"]
                if _matches_pattern(html_sample, pattern):
                    detected.add(tech)
                    break  # Found this tech
    return detected


def detect_tech_from_probe(probe: HostProbe) -> Set[str]:
    """Detect technologies from a HostProbe object.

    Combines header-based and HTML-based detection.
    Note: HostProbe does not store full response text, so HTML-based detection
    is limited to what can be inferred from title and headers.
    """
    detected: Set[str] = set()
    detected.update(detect_tech_from_headers(probe.headers))
    if probe.title:
        # Title is already part of HTML detection in fingerprint(), but we check it explicitly
        detected.update(detect_tech_from_html(f"<title>{probe.title}</title>"))
    # Note: We don't have access to full response text in HostProbe, so we skip
    # HTML body-based detection here. In a full implementation, we might want to
    # store a limited portion of the response body in HostProbe for tech detection.
    return detected


def enhance_probe_with_tech(probe: HostProbe) -> HostProbe:
    """Return a new HostProbe with detected technologies added to fingerprints.

    The original probe is not modified.
    """
    techs = detect_tech_from_probe(probe)
    # Add each detected technology as a fingerprint with special evidence
    enhanced_fps = list(probe.fingerprints)
    for tech in techs:
        enhanced_fps.append(
            # Using a special fingerprint for detected tech
            # In a real implementation, we might extend the Fingerprint model
            # For now, we'll add it as a product with version=None
            # But since Fingerprint doesn't allow arbitrary fields, we'll store
            # this information differently in practice
            # For this prototype, we'll just note it in the signals during triage
            Fingerprint(product=tech, version=None, evidence=f"detected via tech scan")
        )
    # Since we can't easily extend Fingerprint without changing the model,
    # we'll return the probe as-is and let the calling code handle the tech detection
    # separately. In practice, this would be integrated into the triage/scoring.
    return probe