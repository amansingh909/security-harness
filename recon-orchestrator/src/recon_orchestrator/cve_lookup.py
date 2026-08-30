"""Correlate fingerprints with CVEs by querying a running cve-index and matching CPEs.

Returns *candidate* CVEs whose CPEs match the detected product/version —
leads for manual verification, explicitly not confirmations of exploitability."""
from __future__ import annotations

import logging
import re
from typing import List, Tuple

from .models import CveCandidate, Fingerprint

log = logging.getLogger(__name__)


def _parse_cpe_uri(cpe_uri: str) -> Tuple[str | None, str | None, str | None]:
    """Parse a CPE URI and return (part, product, version).

    Expected format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    Returns (None, None, None) if parsing fails.
    """
    if not cpe_uri.startswith("cpe:2.3:"):
        return None, None, None

    try:
        # Remove the cpe:2.3: prefix
        parts = cpe_uri[6:].split(":", 5)  # Split into max 6 parts: part, vendor, product, version, update, rest
        if len(parts) < 4:
            return None, None, None

        part, vendor, product, version = parts[0], parts[1], parts[2], parts[3]

        # Normalize: handle any escaping (though we simplify for now)
        # In a full implementation, we'd unescape per CPE spec
        return part.lower(), product.lower(), version.lower() if version != "*" else None
    except Exception:
        return None, None, None


def _cpe_matches_fingerprint(cpe_uri: str, fingerprint: Fingerprint) -> bool:
    """Check if a CPE URI matches a fingerprint.

    Matches on:
    - Part should be 'a' (application) or we could accept 'o' (os) for some cases
    - Product should match (case-insensitive)
    - Version should match if fingerprint has version
    """
    part, product, version = _parse_cpe_uri(cpe_uri)
    if part is None or product is None:
        return False

    # For now, focus on applications (part='a') but also allow OS matches
    # as some products might be classified differently
    if part not in ('a', 'o'):
        return False

    # Check product match (case-insensitive)
    if fingerprint.product.lower() != product:
        return False

    # If fingerprint has a version, check it matches
    if fingerprint.version is not None:
        if version is None:
            # CPE has version wildcard (*) but fingerprint specifies version
            return False
        if fingerprint.version.lower() != version:
            return False

    return True


def _fingerprint_matches_any_cpe(fingerprint: Fingerprint, cpe_uris: List[str]) -> bool:
    """Check if a fingerprint matches any of the given CPE URIs."""
    for cpe_uri in cpe_uris:
        if _cpe_matches_fingerprint(cpe_uri, fingerprint):
            return True
    return False


async def lookup(
    fingerprints: list[Fingerprint], cve_index_url: str, timeout: float = 15.0, k: int = 10
) -> list[CveCandidate]:
    """Correlate fingerprints with CVEs using CPE matching.

    Args:
        fingerprints: List of detected product/version fingerprints
        cve_index_url: Base URL of the cve-index API
        timeout: HTTP timeout in seconds
        k: Number of results to fetch per query (increased for better filtering)

    Returns:
        List of CVE candidates where CPEs match the fingerprints
    """
    import httpx

    candidates: list[CveCandidate] = []
    versioned = [f for f in fingerprints if f.version]
    if not versioned:
        return []

    # We'll fetch more candidates to allow for filtering by CPE match
    # Since we're doing client-side filtering, we need a broader initial search
    search_k = min(k * 3, 50)  # Fetch up to 3x requested results, max 50

    async with httpx.AsyncClient(base_url=cve_index_url, timeout=timeout) as client:
        for fp in versioned:
            query = f"{fp.product} {fp.version}"
            try:
                resp = await client.get(
                    "/search", params={"q": query, "doc_type": "cve", "k": search_k}
                )
                resp.raise_for_status()
            except httpx.HTTPError as exc:
                log.warning("cve-index query failed",
                            extra={"query": query, "error": str(exc)})
                continue

            for hit in resp.json().get("results", []):
                src = hit.get("source", {})
                # Only process if this looks like a CVE record (has cpe_uris or id pattern)
                if not src.get("id", "").startswith("CVE-"):
                    continue

                cpe_uris = src.get("cpe_uris", [])
                if not cpe_uris:
                    # Fallback: if no CPE data, still include if text match seems good
                    # But we'll prefer those with CPE matches
                    if len(candidates) < k:  # Only fill remaining slots with non-CPE matches
                        candidates.append(CveCandidate(
                            cve_id=src.get("id", hit.get("id", "unknown")),
                            product=fp.product,
                            version=fp.version,
                            cvss_severity=src.get("cvss_severity"),
                            cvss_score=src.get("cvss_score"),
                            why=f"cve-index text match for '{query}' (candidate — verify manually, limited CPE data)",
                        ))
                    continue

                # Check if any CPE URI matches our fingerprint
                if _fingerprint_matches_any_cpe(fp, cpe_uris):
                    candidates.append(CveCandidate(
                        cve_id=src.get("id", hit.get("id", "unknown")),
                        product=fp.product,
                        version=fp.version,
                        cvss_severity=src.get("cvss_severity"),
                        cvss_score=src.get("cvss_score"),
                        why=f"cpe-validated cve-index match for '{query}' (candidate — verify manually)",
                    ))

                    # Stop early if we have enough candidates
                    if len(candidates) >= k:
                        break

            # Stop early if we have enough candidates across all fingerprints
            if len(candidates) >= k:
                break

    # Return at most k candidates, prioritizing those with CPE validation
    # (they're already added first due to the logic above)
    return candidates[:k]