"""Active test vectors and request builder — for AUTHORIZED, OWNER-CONTROLLED
targets only.

This module is only reached when ``Settings.active_tests`` is explicitly True,
and it exists to test assets you own (your own demo/staging projects). It sends
crafted input, which is exactly what bug-bounty programs prohibit — never point
it at a target you do not control.

Design choices that keep detection honest and low-false-positive:

* Reflection uses a **unique marker** (``_XSS_MARKER``), so a hit means *our
  input* came back unencoded — not that the page happened to contain a
  ``<script>`` of its own.
* SQL injection is detected by **database error signatures** in the response,
  not by "the request returned 200".
* Blind SSRF and auth-bypass are deliberately **left out**: neither can be
  confirmed from a single response without an out-of-band listener or a
  baseline, so auto-asserting them would be a false positive. Test those by
  hand.
* No destructive payloads. The original ``{"action":"delete"}`` vector is gone.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass

import httpx

# A token unlikely to occur naturally; if it comes back verbatim, our input was
# reflected without encoding.
_XSS_MARKER = "xsSprobe9f3a2b<>"

# Substrings that indicate the backend leaked a database error.
SQL_ERROR_SIGNATURES: tuple[str, ...] = (
    "sql syntax", "mysql_fetch", "you have an error in your sql",
    "unclosed quotation mark", "quoted string not properly terminated",
    "sqlstate", "ora-0", "psql:", "pg_query", "sqlite error",
    "odbc", "syntax error at or near",
)


@dataclass(frozen=True)
class ActiveTest:
    name: str
    kind: str        # "reflection" | "sql_error"
    param: str
    value: str


# The default set. Each vector is detectable from the response it provokes.
TESTS: tuple[ActiveTest, ...] = (
    ActiveTest("reflected-input", "reflection", "q", _XSS_MARKER),
    ActiveTest("sql-error", "sql_error", "id", "'\"`)"),
)


def _with_query(base: str, param: str, value: str) -> str:
    """Append ``param=value`` to ``base`` with correct URL encoding."""
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}{param}={urllib.parse.quote(value)}"


def build_requests(base_url: str) -> list[tuple[ActiveTest, httpx.Request]]:
    """Build a (test, request) pair for each vector.

    Injects into a query parameter with a GET — the request shape a reflected
    or error-based issue on a page parameter would surface through. Returns the
    test alongside the request so the caller knows how to interpret the
    response.
    """
    out: list[tuple[ActiveTest, httpx.Request]] = []
    for test in TESTS:
        url = _with_query(base_url, test.param, test.value)
        out.append((test, httpx.Request("GET", url)))
    return out


def interpret(test: ActiveTest, body: str) -> str | None:
    """Return a signal string if the response indicates the test fired, else None."""
    if not body:
        return None
    if test.kind == "reflection":
        if test.value in body:
            return (f"reflected input via '{test.param}' (unencoded) — "
                    "possible XSS, verify manually")
    elif test.kind == "sql_error":
        low = body.lower()
        if any(sig in low for sig in SQL_ERROR_SIGNATURES):
            return (f"database error provoked via '{test.param}' — "
                    "possible SQL injection, verify manually")
    return None
