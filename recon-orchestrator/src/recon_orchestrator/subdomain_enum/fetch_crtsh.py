"""Passive subdomain enumeration via crt.sh.

crt.sh is a public Certificate Transparency log aggregator. We query it for
v3 certificates on a target apex and extract all SAN (Subject Alternative
Name) DNS names. This is **passive only** — no outbound DNS resolution, no lookup,
no active probing. Every returned host should already match scope or can be
checked for scope later.

The result is a list of *candidate subdomains* that our recon tooling can then
use as additional seeds for a follow-up pass. We return only names that appear
to legitimately correspond to the target, are not malformed, and are not pure
wildcards.
"""
from __future__ import annotations

import asyncio
import re
import logging
import httpx

# crt.sh is a flaky free service; keep discovery snappy and resilient.
_CRTSH_TIMEOUT = 15.0
_CRTSH_MAX_ATTEMPTS = 3
_CRTSH_BACKOFF = 0.75  # seconds, multiplied by attempt number

log = logging.getLogger(__name__)


_MAX_SAN_COUNT = 200  # cap runaway SAN growth (security]
_STRICT_PATTERN = re.compile(r"^[^.][a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$")


def normalize_subdomain(host: str) -> str | None:
    """Return a cleaned, lowercased subdomain if it looks like a real hostname.

    Rejects empty strings, pure wildcards (e.g. *), and malformed FQDNs.
    A trailing dot is stripped. Hosts are lowercased.
    """
    host = host.strip().lower().rstrip(".")
    if not host:
        return None
    if host.startswith("*."):
        log.warning("crt.sh wildcard ignored",
                     extra={"host": host})
        return None
    if _STRICT_PATTERN.match(host) is None:
        log.debug("crt.sh host rejected as malformed",
                  extra={"host": host})
        return None
    return host


def _parse_crtsh_page(html: str, apex: str) -> set[str]:
    """Extract names from crt.sh CRIR Report HTML (very lightweight).

    crt.sh returns a table of certificate records. We only care about SAN entries
    that appear to reference the target apex. The parsing regex is conservative
    and tolerant to minor HTML variation (we never trust incomplete data).
    """
    import re

    # Normalize apex lowercased for matching.
    apex_norm = apex.lower()
    names: set[str] = set()

    # Find all occurrences of "- <hostname>" pattern.
    # The hostname is everything between "<" and ">" after a "- <".
    for match in re.finditer(r'- <([^>]+)>', html):
        hostname = match.group(1).strip()
        host = normalize_subdomain(hostname)
        if host and host.endswith(f".{apex_norm}"):
            names.add(host)
    return names


async def fetch_crtsh_for_apex(apex: str) -> set[str]:
    """Query ARIA (crt.sh's search) for the given apex and return candidate subdomains.

    Returns a set of normalized, lowercase, validated subdomains.
    """
    apex = apex.strip().lower()
    if not apex:
        log.warning("crt.sh query aborted: empty apex")
        return set()

    url = "https://crt.sh/?q=%25." + apex + "&output=json"
    headers = {"User-Agent": "recon-orchestrator (authorized security testing)"}

    # crt.sh is a free service that frequently returns 502/503 or times out.
    # Retry the transient cases a couple of times, then give up quietly —
    # discovery is an optional enrichment, not a hard dependency.
    html: str | None = None
    last_error = ""
    for attempt in range(_CRTSH_MAX_ATTEMPTS):
        try:
            async with httpx.AsyncClient(timeout=_CRTSH_TIMEOUT, headers=headers) as client:
                resp = await client.get(url)
            if resp.status_code == 200:
                html = resp.text
                break
            # 502/503/504/429 are crt.sh being overloaded — worth a retry.
            if resp.status_code in (429, 500, 502, 503, 504):
                last_error = f"HTTP {resp.status_code}"
            else:
                last_error = f"HTTP {resp.status_code}"
                break  # a 4xx we caused won't fix itself on retry
        except httpx.HTTPError as exc:
            last_error = type(exc).__name__

        if attempt + 1 < _CRTSH_MAX_ATTEMPTS:
            await asyncio.sleep(_CRTSH_BACKOFF * (attempt + 1))

    if html is None:
        # Non-fatal: recon proceeds on the seeds without discovered subdomains.
        log.info("crt.sh unavailable, skipping subdomain discovery",
                 extra={"apex": apex, "reason": last_error})
        return set()

    raw_names = _parse_crtsh_page(html, apex)
    if not raw_names:
        log.debug("crt.sh returned no valid subdomains",
                  extra={"apex": apex})
    else:
        log.info("crtsh returned subdomains",
                 extra={"apex": apex, "count": len(raw_names)})
    return raw_names