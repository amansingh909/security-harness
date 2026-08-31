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

from dataclasses import dataclass

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
    value: str       # the payload injected into a discovered parameter


# The default set. Each vector is detectable from the response it provokes.
# The parameter to inject into comes from endpoint discovery, not from here.
TESTS: tuple[ActiveTest, ...] = (
    ActiveTest("reflected-input", "reflection", _XSS_MARKER),
    ActiveTest("sql-error", "sql_error", "'\"`)"),
)


def interpret(test: ActiveTest, body: str) -> str | None:
    """Return a vuln description if the response shows the test fired, else None.

    The caller tags this with the endpoint and parameter it was fired at.
    """
    if not body:
        return None
    if test.kind == "reflection":
        if test.value in body:
            return "reflected input (unencoded) — possible XSS"
    elif test.kind == "sql_error":
        low = body.lower()
        if any(sig in low for sig in SQL_ERROR_SIGNATURES):
            return "database error provoked — possible SQL injection"
    return None
