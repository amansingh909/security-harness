"""Hacktivity dedup: check a finding against HackerOne's public disclosures.

The fixture mirrors the real Hacker API hacktivity response shape (verified
against api.hackerone.com): a program's handle rides on each item under
relationships.program.data.attributes.handle, and the queryString the API honors
is `disclosed:true` + free text (it ignores a `program:` field, so we scope
client-side).
"""
from __future__ import annotations

from harness import dedup

# One CLEAR item, one other-program item — same vuln class, different program.
SAMPLE = {
    "data": [
        {
            "type": "hacktivity_item",
            "attributes": {
                "title": "Stored XSS in the member dashboard",
                "substate": "resolved",
                "url": "https://hackerone.com/reports/12345",
                "disclosed_at": "2024-01-02T00:00:00Z",
                "cve_ids": ["CVE-2024-0001"],
                "cwe": "CWE-79",
                "severity_rating": "high",
                "votes": 12,
                "disclosed": True,
            },
            "relationships": {"program": {"data": {
                "type": "program",
                "attributes": {"handle": "clear", "name": "CLEAR"}}}},
        },
        {
            "type": "hacktivity_item",
            "attributes": {
                "title": "Reflected XSS somewhere else entirely",
                "url": "https://hackerone.com/reports/999",
                "cve_ids": [], "cwe": None, "severity_rating": "medium",
                "votes": 3, "disclosed": True,
            },
            "relationships": {"program": {"data": {
                "type": "program",
                "attributes": {"handle": "someone-else", "name": "Someone Else"}}}},
        },
    ],
    "links": {},
}


def _stub(monkeypatch, captured=None):
    def fake(url, params, auth, timeout):
        if captured is not None:
            captured["url"] = url
            captured["params"] = params
            captured["auth"] = auth
        return SAMPLE
    monkeypatch.setattr(dedup, "_http_get_json", fake)


def test_search_disclosed_parses_the_real_item_shape(monkeypatch):
    _stub(monkeypatch)
    reports = dedup.search_disclosed("xss", identifier="id", token="tok")
    assert [r.url for r in reports] == [
        "https://hackerone.com/reports/12345",
        "https://hackerone.com/reports/999",
    ]
    first = reports[0]
    assert first.title == "Stored XSS in the member dashboard"
    assert first.program == "clear"          # pulled from the nested relationship
    assert first.severity == "high"
    assert first.cwe == "CWE-79"
    assert first.cve_ids == ["CVE-2024-0001"]
    assert first.votes == 12


def test_query_is_scoped_to_disclosed_and_carries_keywords(monkeypatch):
    captured = {}
    _stub(monkeypatch, captured)
    dedup.search_disclosed("idor account", identifier="id", token="tok")
    qs = captured["params"]["queryString"]
    assert qs.startswith("disclosed:true")
    assert "idor" in qs and "account" in qs
    assert captured["auth"] == ("id", "tok")   # HTTP Basic identifier:token


def test_dedup_candidates_keeps_only_the_target_program(monkeypatch):
    _stub(monkeypatch)
    matches = dedup.dedup_candidates("clear", "xss", identifier="id", token="tok")
    assert [m.url for m in matches] == ["https://hackerone.com/reports/12345"]
    # the other-program XSS is dropped — a different program is not a duplicate
    assert all(m.program == "clear" for m in matches)


def test_dedup_candidates_is_case_insensitive_on_handle(monkeypatch):
    _stub(monkeypatch)
    assert dedup.dedup_candidates("CLEAR", "xss", identifier="id", token="tok")


def test_dedup_candidates_seeds_the_program_handle_into_the_search(monkeypatch):
    # The API can't filter by program, so the handle is seeded as a free-text
    # bias term (and still enforced exactly client-side).
    captured = {}
    _stub(monkeypatch, captured)
    dedup.dedup_candidates("clear", "idor account", identifier="id", token="tok")
    qs = captured["params"]["queryString"]
    assert "clear" in qs and "idor" in qs and qs.startswith("disclosed:true")


def test_dedup_drops_redacted_items_without_a_url(monkeypatch):
    payload = {"data": [
        {"attributes": {"title": "", "url": "", "cve_ids": [], "votes": 0},
         "relationships": {"program": {"data": {"attributes": {"handle": "clear"}}}}},
        {"attributes": {"title": "Real one", "url": "https://hackerone.com/reports/5",
                        "cve_ids": [], "votes": 1},
         "relationships": {"program": {"data": {"attributes": {"handle": "clear"}}}}},
    ]}
    monkeypatch.setattr(dedup, "_http_get_json", lambda *a, **k: payload)
    out = dedup.dedup_candidates("clear", "xss", identifier="id", token="tok")
    assert [r.url for r in out] == ["https://hackerone.com/reports/5"]


def test_no_credentials_returns_empty(monkeypatch):
    monkeypatch.delenv("H1_IDENTIFIER", raising=False)
    monkeypatch.delenv("H1_API_KEY", raising=False)
    assert dedup.dedup_candidates("clear", "xss") == []


def test_network_error_degrades_to_empty(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("hackerone unreachable")
    monkeypatch.setattr(dedup, "_http_get_json", boom)
    assert dedup.search_disclosed("xss", identifier="id", token="tok") == []


def test_keywords_for_builds_a_clean_query():
    q = dedup.keywords_for("reflected input (unencoded) — possible XSS at /Search.asp",
                           "testasp.vulnweb.com")
    toks = q.split()
    assert "reflected" in q and "XSS" in q and "Search.asp" in q
    assert "testasp.vulnweb.com" in toks
    # stopwords and 1-2 char noise are dropped
    assert "possible" not in toks and "at" not in toks
    assert len(toks) <= 8
