"""Optional: enrich a finding with CVE context from a running cve-index API.

Extracts CVE ids referenced anywhere in the finding text and fetches their
records so the report can cite accurate CVE metadata instead of the model's
recollection (which is exactly where CVE hallucinations creep in)."""
from __future__ import annotations

import logging
import re

from .models import Finding

log = logging.getLogger(__name__)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def referenced_cve_ids(finding: Finding) -> list[str]:
    blob = " ".join(
        [finding.summary or "", finding.impact, finding.observed_result]
        + finding.references
    )
    seen: list[str] = []
    for match in _CVE_RE.findall(blob):
        cid = match.upper()
        if cid not in seen:
            seen.append(cid)
    return seen


async def enrich(finding: Finding, cve_index_url: str, timeout: float = 15.0) -> list[dict]:
    """Return verified CVE records for ids mentioned in the finding."""
    import httpx

    ids = referenced_cve_ids(finding)
    if not ids:
        return []
    records: list[dict] = []
    async with httpx.AsyncClient(base_url=cve_index_url, timeout=timeout) as client:
        for cid in ids:
            try:
                resp = await client.get(f"/cve/{cid}")
                if resp.status_code == 200:
                    records.append(resp.json())
                else:
                    log.warning("cve not found in index",
                                extra={"cve": cid, "status": resp.status_code})
            except httpx.HTTPError as exc:
                log.warning("cve-index lookup failed",
                            extra={"cve": cid, "error": str(exc)})
    return records
