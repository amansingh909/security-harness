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

- H1_API_KEY : HackerOne API token (Basic auth: token:)
- BC_API_KEY : Bugcrowd API token (token auth: Token <token>)
"""

from __future__ import annotations

import json
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
    cvss_score = first_cve.get("cvss_score")
    # We don't have CWE from the batch report; leave None.
    cwe = None

    # Asset string for Bugcrowd
    asset = f"{host}:{port}" if port else host

    # Placeholder text – the user should replace this with real PoC steps
    steps = (
        "Automated scan detected a potential vulnerability. "
        "See the full report for technical details."
    )
    observed = "Potential vulnerability identified via automated recon."
    impact = "Potential security issue affecting the asset."

    return Finding(
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


def upload_report(
    report_path: Path | str,
    program: str,
    h1_api_key: str | None,
    bc_api_key: str | None,
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

            # HackerOne
            if h1_api_key:
                payload = hackerone.to_submission(
                    finding,
                    markdown="",  # markdown not required for submission; we can leave empty
                    rating="UNKNOWN",  # we don't have a rating; will map to "none"
                    cvss_score=None if finding.cvss_vector is None else float(finding.cvss_vector.split("/")[1]) if "/" in finding.cvss_vector else 5.0,  # rough fallback
                    cwe=finding.cwe,
                )
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {h1_api_key}",
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

        # Run all requests concurrently (limited concurrency to avoid rate limits)
        semaphore = httpx.AsyncHTTPTransport(retries=2)  # not ideal; we'll just gather with a semaphore via asyncio
        # Simpler: use asyncio.Semaphore inside a wrapper
        async def _sem_post(url, payload, headers, sem: asyncio.Semaphore):
            async with sem:
                return await _post_json(url, payload, headers)

        # We'll create the semaphores inside the function; need asyncio imported
        import asyncio

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