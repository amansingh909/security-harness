"""Hacktivity dedup — check a finding against HackerOne's public disclosures.

Before the operator submits, this surfaces already-disclosed reports so they
don't file a known duplicate. It is a read-only sanity aid, never a verdict: it
lists candidates for a human to eyeball.

How it works (verified against api.hackerone.com/v1/hackers/hacktivity):

* Auth is HTTP Basic ``identifier:token`` (H1_IDENTIFIER + H1_API_KEY, loaded
  from ~/.harness/.env like the rest of the harness).
* The API's ``queryString`` honors ``disclosed:true`` and free-text search, but
  it ignores a ``program:`` field. Each item does carry its program handle inline
  (relationships.program.data.attributes.handle), so we over-fetch by keyword and
  scope to the target program client-side.
* Any failure (no creds, network error, schema drift) degrades to an empty list
  — a missing dedup check must never block the review flow.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

HACKTIVITY_URL = "https://api.hackerone.com/v1/hackers/hacktivity"

# Free-text noise to drop when building a query from a finding's prose.
_STOP = {
    "the", "and", "via", "for", "with", "from", "that", "this", "was", "are",
    "possible", "http", "https",
}


@dataclass
class DisclosedReport:
    title: str
    url: str
    program: str                       # program handle, e.g. "clear"
    severity: str | None = None
    cwe: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    disclosed_at: str | None = None
    votes: int = 0


def _item_program(item: dict) -> str:
    data = ((item.get("relationships") or {}).get("program") or {}).get("data") or {}
    return str((data.get("attributes") or {}).get("handle") or "")


def _to_report(item: dict) -> DisclosedReport:
    a = item.get("attributes") or {}
    return DisclosedReport(
        title=a.get("title") or "",
        url=a.get("url") or "",
        program=_item_program(item),
        severity=a.get("severity_rating"),
        cwe=a.get("cwe"),
        cve_ids=list(a.get("cve_ids") or []),
        disclosed_at=a.get("disclosed_at"),
        votes=int(a.get("votes") or 0),
    )


def _http_get_json(url, params, auth, timeout):
    """The one network call, isolated so tests can stub it. Raises on error."""
    import httpx

    resp = httpx.get(url, params=params, auth=auth, timeout=timeout,
                     headers={"Accept": "application/json"})
    resp.raise_for_status()
    return resp.json()


def search_disclosed(query: str, *, identifier: str, token: str,
                     limit: int = 25, timeout: float = 15.0) -> list[DisclosedReport]:
    """Disclosed hacktivity reports matching a free-text query. [] on any error."""
    # No explicit sort: the API's default is relevance ranking, which (with the
    # program handle seeded into the query) surfaces the program's matching
    # reports. Sorting by recency instead buries them under unrelated activity.
    params = {
        "queryString": f"disclosed:true {query}".strip(),
        "page[size]": max(1, min(int(limit), 100)),
    }
    try:
        data = _http_get_json(HACKTIVITY_URL, params, (identifier, token), timeout)
    except Exception:
        return []
    return [_to_report(it) for it in (data.get("data") or [])]


def dedup_candidates(program_handle: str, query: str, *, identifier: str | None = None,
                     token: str | None = None, limit: int = 25,
                     timeout: float = 15.0) -> list[DisclosedReport]:
    """Disclosed reports for ``program_handle`` matching ``query``.

    The API can't filter by program, so we over-fetch by keyword and keep only
    the items whose program handle matches (case-insensitive). Credentials
    default to the environment (H1_IDENTIFIER / H1_API_KEY).
    """
    identifier = identifier or os.getenv("H1_IDENTIFIER")
    token = token or os.getenv("H1_API_KEY")
    if not identifier or not token:
        return []
    handle = (program_handle or "").strip().lower()
    # The API ignores a `program:` filter, so bias the free-text search toward
    # the program by seeding its handle, then scope precisely client-side.
    search_query = f"{handle} {query}".strip() if handle else query
    hits = search_disclosed(search_query, identifier=identifier, token=token,
                            limit=limit, timeout=timeout)
    # Keep only this program's items that actually carry a report URL; items
    # with a known program but null content are redacted and not actionable.
    return [r for r in hits if r.program.lower() == handle and r.url]


def keywords_for(*parts: object, max_tokens: int = 8) -> str:
    """Build a compact free-text query from a finding's fields (vuln type, host,
    signal snippets). Keeps distinctive tokens, drops stopwords and short noise,
    preserves original case, and caps length so the query stays focused."""
    seen: set[str] = set()
    out: list[str] = []
    for part in parts:
        for tok in re.findall(r"[A-Za-z0-9][A-Za-z0-9.\-]{2,}", str(part or "")):
            low = tok.lower()
            if low in seen or low in _STOP:
                continue
            seen.add(low)
            out.append(tok)
            if len(out) >= max_tokens:
                return " ".join(out)
    return " ".join(out)
