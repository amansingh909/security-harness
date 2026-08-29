"""Correlate fingerprints with CVEs by querying a running cve-index.

Returns *candidate* CVEs whose metadata mentions the detected product/version —
leads for manual verification, explicitly not confirmations of exploitability."""
from __future__ import annotations

import logging

from .models import CveCandidate, Fingerprint

log = logging.getLogger(__name__)


async def lookup(
    fingerprints: list[Fingerprint], cve_index_url: str, timeout: float = 15.0, k: int = 5
) -> list[CveCandidate]:
    import httpx

    candidates: list[CveCandidate] = []
    versioned = [f for f in fingerprints if f.version]
    if not versioned:
        return []
    async with httpx.AsyncClient(base_url=cve_index_url, timeout=timeout) as client:
        for fp in versioned:
            query = f"{fp.product} {fp.version}"
            try:
                resp = await client.get(
                    "/search", params={"q": query, "doc_type": "cve", "k": k}
                )
                resp.raise_for_status()
            except httpx.HTTPError as exc:
                log.warning("cve-index query failed",
                            extra={"query": query, "error": str(exc)})
                continue
            for hit in resp.json().get("results", []):
                src = hit.get("source", {})
                candidates.append(CveCandidate(
                    cve_id=src.get("id", hit.get("id", "unknown")),
                    product=fp.product,
                    version=fp.version,
                    cvss_severity=src.get("cvss_severity"),
                    cvss_score=src.get("cvss_score"),
                    why=f"cve-index match for '{query}' (candidate — verify manually)",
                ))
    return candidates
