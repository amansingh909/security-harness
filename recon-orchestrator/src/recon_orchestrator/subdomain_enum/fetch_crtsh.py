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

import re
import logging
import httpx

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

    # crt.sh's CRIR Report endpoint uses a form parameter.
    url = "https://crt.sh/?q=%25." + apex + "&output=json"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
        # Re-encode it as HTML soup we can parse with our lightweight regex.
        html = resp.text
    except httpx.HTTPError as exc:
        log.warning("crt.sh query failed",
                    extra={"apex": apex, "error": str(exc)})
        return set()

    raw_names = _parse_crtsh_page(html, apex)
    if not raw_names:
        log.debug("crt.sh returned no valid subdomains",
                  extra={"apex": apex})
    else:
        log.info("crtsh returned subdomains",
                 extra={"apex": apex, "count": len(raw_names)})
    return raw_names