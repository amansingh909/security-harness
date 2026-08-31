"""Upload findings to HackerOne and/or Bugcrowd APIs.

This module is intentionally lightweight: it reads a batch JSON report
produced by ``engine.render_batch_report``, converts each vulnerability
into a ``Finding`` object, builds a submission payload using the existing
``hackerone.to_submission`` and ``bugcrowd.to_submission`` helpers, and
POSTs the JSON to the respective platforms.

All network calls are simple POSTs with JSON payloads. Errors are caught
and logged; the function returns a dict with counts of successes and
failures for each platform.

Environment variables (or explicit arguments) are expected to contain the
API tokens:

- H1_IDENTIFIER : HackerOne API identifier (username half of the credential)
- H1_API_KEY    : HackerOne API token; sent as Basic identifier:token
- BC_API_KEY    : Bugcrowd API token (token auth: Token <token>)
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
from pathlib import Path
from typing import Dict, Any, Tuple

import httpx

from .models import Finding
from . import hackerone, bugcrowd


def _build_finding(
    program: str,
    vuln: dict,
) -> Finding:
    """Convert a vulnerability dict from the batch report into a Finding.

    The batch report dict contains:
        - host, service (dict with host, port, scheme, server, powered_by,
          status_code, optional title)
        - cves: list of dicts with id, cvss_vector, cvss_score,
          exploit_available
        - priority_score: float

    We create a minimal Finding with placeholder text for the required
    fields (steps_to_reproduce, observed_result, impact). The title
    describes the service; the asset is the host:port. If a CVE is present,
    we use its CVSS vector and score; otherwise we leave them empty.
    """
    service = vuln.get("service", {})
    host = service.get("host", "")
    port = service.get("port", "")
    scheme = service.get("scheme", "http")
    server = service.get("server", "unknown")
    powered_by = service.get("powered_by", "unknown")
    title = service.get("title") or f"{scheme.upper()} service on {host}:{port}"

    # Use the first CVE (if any) for CVSS/CWE fields
    first_cve = vuln.get("cves", [{}])[0] if vuln.get("cves") else {}
    cvss_vector = first_cve.get("cvss_vector")
    # cvss_score is read by the caller straight off the vuln dict; Finding has
    # no field for it.
    # We don't have CWE from the batch report; leave None.
    cwe = None

    # Asset string for Bugcrowd
    asset = f"{host}:{port}" if port else host

    # Finding.vuln_type is required. Name the CVE when we have one, otherwise
    # describe what the scan actually observed.
    cve_id = first_cve.get("id")
    vuln_type = (
        f"Known vulnerability {cve_id} in exposed service" if cve_id
        else "Exposed service with potentially vulnerable software version"
    )

    # steps_to_reproduce is a list[str] with min_length=1 — a single string
    # fails validation. Include the fingerprint that triggered the match so the
    # steps are reproducible rather than a bare placeholder.
    steps = [
        f"Request {scheme}://{asset} over {scheme.upper()}.",
        f"Observe the response banner: server={server}, x-powered-by={powered_by}.",
        (
            f"Compare that version against {cve_id}."
            if cve_id
            else "Compare the reported version against known advisories."
        ),
        "See the attached batch report for the full scan output.",
    ]
    observed = (
        f"{host}:{port} responds with server={server!r}, x-powered-by={powered_by!r}"
        + (f", matching {cve_id}." if cve_id else ".")
    )
    impact = "Potential security issue affecting the asset."

    return Finding(
        vuln_type=vuln_type,
        title=title,
        steps_to_reproduce=steps,
        observed_result=observed,
        impact=impact,
        cvss_vector=cvss_vector,
        cwe=cwe,
        program=program,
        asset=asset,
        # No PoC request/response from the scanner
        poc_request=None,
        poc_response=None,
        references=[],
    )


def _h1_auth_header(identifier: str, token: str) -> str:
    """Build HackerOne's Authorization header.

    HackerOne authenticates with HTTP Basic, not Bearer: the API identifier is
    the username half and the API token is the password half, joined by a colon
    and base64-encoded. Sending ``Bearer <token>`` returns 401 every time.
    """
    raw = f"{identifier}:{token}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def upload_report(
    report_path: Path | str,
    program: str,
    h1_api_key: str | None,
    bc_api_key: str | None,
    h1_identifier: str | None = None,
) -> Dict[str, Any]:
    """
    Upload all findings in ``report_path`` to HackerOne and/or Bugcrowd.

    Parameters
    ----------
    report_path: pathlib.Path or str
        Path to the JSON batch report (e.g., ``~/hints/prog/prog_report.json``).
    program: str
        Program name – used as the ``team_handle`` for HackerOne and as context.
    h1_api_key: str | None
        HackerOne API token. If ``None``, HackerOne upload is skipped.
    bc_api_key: str | None
        Bugcrowd API token. If ``None``, Bugcrowd upload is skipped.
    h1_identifier: str | None
        HackerOne API identifier (the username half of the credential, shown
        beside the token under Settings -> API Tokens). Falls back to the
        ``H1_IDENTIFIER`` environment variable. HackerOne authenticates with
        HTTP Basic ``identifier:token`` — the token alone is not enough.

    Returns
    -------
    dict with keys:
        - ``hackerone``: ``{sent: int, failed: int, errors: list[str]}``
        - ``bugcrowd``: same structure
    """
    report_path = Path(report_path)
    if not report_path.is_file():
        raise FileNotFoundError(f"Report not found: {report_path}")

    data = json.loads(report_path.read_text(encoding="utf-8"))
    vulns: list[dict] = data.get("vulnerabilities", [])

    # Resolve the HackerOne identifier once and fail up front, rather than
    # letting every finding 401 individually.
    h1_identifier = h1_identifier or os.getenv("H1_IDENTIFIER")
    if h1_api_key and not h1_identifier:
        raise ValueError(
            "HackerOne needs an API identifier as well as a token. Find it under "
            "Settings -> API Tokens and set H1_IDENTIFIER in ~/.harness/.env."
        )

    results: Dict[str, Any] = {
        "hackerone": {"sent": 0, "failed": 0, "errors": []},
        "bugcrowd": {"sent": 0, "failed": 0, "errors": []},
    }

    # Helper to perform a POST with appropriate headers
    async def _post_json(url: str, payload: dict, headers: dict) -> Tuple[bool, str]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code in (200, 201):
                    return True, ""
                else:
                    return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
            except Exception as exc:  # noqa: BLE001
                return False, f"{type(exc).__name__}: {exc}"

    async def _process_all() -> None:
        tasks_h1: list[tuple] = []
        tasks_bc: list[tuple] = []

        for vuln in vulns:
            finding = _build_finding(program, vuln)
            # The scan already carries a numeric score. Deriving one from the
            # vector string does not work — splitting "CVSS:3.1/AV:N/AC:L" on
            # "/" yields "AV:N", and float("AV:N") raises.
            cvss_score = ((vuln.get("cves") or [{}])[0]).get("cvss_score")

            # HackerOne
            if h1_api_key:
                payload = hackerone.to_submission(
                    finding,
                    markdown="",  # markdown not required for submission; we can leave empty
                    rating="UNKNOWN",  # we don't have a rating; will map to "none"
                    cvss_score=cvss_score,
                    cwe=finding.cwe,
                )
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": _h1_auth_header(h1_identifier, h1_api_key),
                }
                tasks_h1.append(
                    (
                        "https://api.hackerone.com/v1/reports",
                        payload,
                        headers,
                    )
                )

            # Bugcrowd
            if bc_api_key:
                payload = bugcrowd.to_submission(
                    finding,
                    markdown="",
                    rating="UNKNOWN",
                    cwe=finding.cwe,
                )
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Token {bc_api_key}",
                }
                tasks_bc.append(
                    (
                        "https://api.bugcrowd.com/submissions",
                        payload,
                        headers,
                    )
                )

        # Run all requests concurrently, capped so we stay polite to the API.
        async def _sem_post(url, payload, headers, sem: asyncio.Semaphore):
            async with sem:
                return await _post_json(url, payload, headers)

        sem = asyncio.Semaphore(5)

        async def gather_and_update(tasks, platform_key: str):
            coros = [
                _sem_post(url, payload, headers, sem) for (url, payload, headers) in tasks
            ]
            for idx, (ok, err) in enumerate(await asyncio.gather(*coros)):
                if ok:
                    results[platform_key]["sent"] += 1
                else:
                    results[platform_key]["failed"] += 1
                    results[platform_key]["errors"].append(err)

        await gather_and_update(tasks_h1, "hackerone")
        await gather_and_update(tasks_bc, "bugcrowd")

    # Run the async processing
    asyncio.run(_process_all())

    return results