"""Glue between the TUI and the harness components.

Imports are lazy so the TUI still launches if a component isn't installed yet;
each function raises a clear, catchable error the UI can surface instead."""
from __future__ import annotations

import asyncio
import socket
import ssl
from typing import List, Dict, Any, Optional

from .programs import Program


class ComponentMissing(RuntimeError):
    """A required sibling component isn't importable/installed."""


def _target_headers(program: Program) -> dict[str, str]:
    """Headers to put on EVERY request to a program's assets.

    Program-required testing headers (e.g. ``X-Bug-Bounty``) plus the Vercel
    protection-bypass header when configured. A program that requires a header
    forfeits the reward if any request is missing it, so both the recon prober
    and the separate scan/fingerprint client build their headers from here.
    """
    import os

    headers: dict[str, str] = dict(program.extra_headers or {})
    bypass = os.getenv("VERCEL_AUTOMATION_BYPASS_SECRET")
    if bypass:
        headers["x-vercel-protection-bypass"] = bypass
        headers["x-vercel-set-bypass-cookie"] = "true"
    return headers


async def run_recon(program: Program) -> list[dict]:
    """Run recon for a program via recon_orchestrator; return candidate leads."""
    try:
        from recon_orchestrator.config import Settings
        from recon_orchestrator.orchestrator import run_recon as _run
        from recon_orchestrator.scope import ScopeGuard
    except ImportError as exc:  # pragma: no cover - env dependent
        raise ComponentMissing(
            "recon-orchestrator not installed. Run: pip install -e ../recon-orchestrator"
        ) from exc

    seeds = list(program.seeds)
    if program.seeds_file:
        try:
            with open(program.seeds_file, encoding="utf-8") as fh:
                seeds += [
                    line.strip()
                    for line in fh
                    if line.strip() and not line.startswith("#")
                ]
        except OSError as exc:
            raise ComponentMissing(f"seeds_file unreadable: {exc}") from exc

    import os

    # Program-required testing headers + any Vercel bypass, on every request.
    extra_headers = _target_headers(program)
    settings = Settings(
        requests_per_second=program.requests_per_second,
        cve_index_url=program.cve_index_url,
        # Active testing is per-program and owned-assets-only. ZAP credentials
        # come from the environment (~/.harness/.env), never the program file.
        active_tests=program.active_tests,
        use_zap=program.use_zap,
        zap_api_url=os.getenv("ZAP_API_URL"),
        zap_api_key=os.getenv("ZAP_API_KEY"),
        extra_request_headers=extra_headers,
    )
    scope = ScopeGuard(
        program.in_scope, program.out_of_scope, program.allow_multilevel_wildcard
    )
    return await _run(settings, scope, seeds)


async def search_cve(query: str, cve_index_url: str, k: int = 10) -> list[dict]:
    """Query a running cve-index API for CVEs/techniques."""
    import httpx

    async with httpx.AsyncClient(base_url=cve_index_url, timeout=15) as client:
        resp = await client.get("/search", params={"q": query, "k": k})
        resp.raise_for_status()
        return resp.json().get("results", [])


def render_report(finding_path: str) -> dict:
    """Render a filled finding file to HackerOne/Bugcrowd/Markdown artifacts.

    Returns {"out_dir", "fingerprint", "rating", "cvss"}. Raises ComponentMissing
    if bounty-reporter isn't installed, or ValueError with the friendly
    missing-evidence message if the scaffold's required fields aren't filled."""
    import json
    from pathlib import Path

    import yaml

    try:
        from bounty_reporter.generator import generate
        from bounty_reporter.models import Finding
    except ImportError as exc:  # pragma: no cover - env dependent
        raise ComponentMissing(
            "bounty-reporter not installed. Run: pip install -e ../bounty-reporter"
        ) from exc

    from .findings import unfilled_todos

    data = yaml.safe_load(Path(finding_path).read_text(encoding="utf-8")) or {}
    data.pop("_recon_context", None)
    todos = unfilled_todos(data)
    if todos:
        raise ValueError(
            "still has TODO placeholders in: " + ", ".join(todos)
            + ". Fill them from your manual testing first."
        )
    finding = Finding.from_dict(data)
    report = generate(finding)

    out_dir = Path(finding_path).parent / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir / report.fingerprint
    base.with_suffix(".md").write_text(report.markdown, encoding="utf-8")
    (out_dir / f"{report.fingerprint}.hackerone.json").write_text(
        json.dumps(report.hackerone, indent=2), encoding="utf-8")
    (out_dir / f"{report.fingerprint}.bugcrowd.json").write_text(
        json.dumps(report.bugcrowd, indent=2), encoding="utf-8")
    return {
        "out_dir": str(out_dir),
        "fingerprint": report.fingerprint,
        "rating": report.rating,
        "cvss": report.cvss_score,
    }


def _humanize_evidence(evidence: dict) -> dict:
    """Return a copy of a finding dict with only its NARRATIVE fields de-AI'd.

    Humanizes summary / impact / remediation; leaves reproduction steps,
    request/response, observed_result, and CVSS byte-for-byte — the humanizer
    never gets a second chance to touch evidence.
    """
    from .humanizer import humanize

    out = dict(evidence)
    for field in ("summary", "impact", "remediation"):
        if out.get(field):
            out[field] = humanize(out[field])
    return out


def draft_report(finding: dict) -> str:
    """Render a submittable Markdown report from a VERIFIED finding, prose humanized.

    Builds a bounty_reporter Finding (which refuses missing or blank evidence)
    from the humanized finding, then renders Markdown. Raises ValueError if the
    finding lacks real evidence.
    """
    try:
        from bounty_reporter.generator import generate
        from bounty_reporter.models import Finding
    except ImportError as exc:  # pragma: no cover - env dependent
        raise ComponentMissing(
            "bounty-reporter not installed. Run: pip install -e ../bounty-reporter"
        ) from exc

    model = Finding.from_dict(_humanize_evidence(finding))
    return generate(model).markdown


def submit_finding(
    evidence: dict,
    program: str,
    *,
    h1_key: str | None = None,
    bc_key: str | None = None,
    h1_identifier: str | None = None,
) -> dict:
    """Submit ONE verified finding to the program(s), prose humanized.

    Humanizes the narrative fields, refuses up front if the evidence is missing
    or blank (so nothing unverified is ever sent), writes a one-item batch and
    POSTs it through the anti-fabrication uploader. Returns the uploader's
    ``{hackerone, bugcrowd}`` result.
    """
    try:
        from bounty_reporter.models import Finding
        from bounty_reporter.uploader import upload_report
    except ImportError as exc:  # pragma: no cover - env dependent
        raise ComponentMissing(
            "bounty-reporter not installed. Run: pip install -e ../bounty-reporter"
        ) from exc

    import json
    import os as _os
    import tempfile

    humanized = _humanize_evidence({**evidence, "program": program})
    Finding.from_dict(humanized)  # raises ValueError if evidence is missing/blank

    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, encoding="utf-8"
    ) as fh:
        json.dump({"vulnerabilities": [humanized]}, fh)
        path = fh.name
    try:
        return upload_report(path, program, h1_key, bc_key, h1_identifier)
    finally:
        _os.unlink(path)


def available() -> dict[str, bool]:
    """Which sibling components are importable in this environment."""
    import importlib.util

    def has(module: str) -> bool:
        try:
            return importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):
            return False

    return {
        "recon": has("recon_orchestrator"),
        "reporter": has("bounty_reporter"),
        # classifier inference needs both the package and the torch stack
        "classifier": has("cve_classifier") and has("torch"),
    }


async def cve_index_health(url: str) -> dict:
    """Ping a cve-index API's /health. Returns {up, vectors}."""
    import httpx

    try:
        async with httpx.AsyncClient(base_url=url, timeout=4) as client:
            resp = await client.get("/health")
            resp.raise_for_status()
            data = resp.json()
            return {"up": bool(data.get("elasticsearch")), "vectors": data.get("vectors")}
    except Exception:  # noqa: BLE001 - health check must never raise
        return {"up": False, "vectors": None}


async def scan_for_vulns(program: Program, leads: list[dict]) -> list[dict]:
    """Scan leads for known CVEs via cve-index API with CPE matching.

    For each lead, attempt to fingerprint the service and search for CVEs using
    CPE-based matching for more accurate version-specific results.
    Returns list of vulnerability findings.
    """
    try:
        import httpx
        from recon_orchestrator.config import Settings
        from recon_orchestrator.cve_lookup import lookup
        from recon_orchestrator.models import Fingerprint
    except ImportError as exc:
        raise ComponentMissing(
            "recon-orchestrator not installed or missing dependencies. "
            "Run: pip install -e ../recon-orchestrator"
        ) from exc

    vulns = []

    # Use a reasonable timeout and limit concurrent requests. The scan step has
    # its own client, so it must carry the program's required headers too.
    async with httpx.AsyncClient(
        timeout=10.0, headers=_target_headers(program)
    ) as client:
        for lead in leads:
            host = lead.get("host")
            if not host:
                continue

            # Try to get service information from common ports
            service_info = await _fingerprint_service(client, host)
            if not service_info:
                continue

            # Convert service info to fingerprints for CPE matching
            fingerprints = []

            # Check server header (e.g., "nginx/1.18.0")
            server = service_info.get("server", "")
            if server:
                # Try to extract product and version from server header
                # Common formats: "nginx/1.18.0", "Apache/2.4.41", etc.
                parts = server.split("/")
                if len(parts) >= 2:
                    product = parts[0].strip()
                    version = parts[1].split()[0].strip()  # Take first part before space
                    # Validate that version looks like a version number
                    if version and any(c.isdigit() for c in version):
                        fingerprints.append(Fingerprint(
                            product=product,
                            version=version,
                            evidence=f"Server header: {server}"
                        ))
                # Also try without version splitting for cases like "Microsoft-IIS/10.0"
                elif server and any(c.isdigit() for c in server):
                    # Try to find version pattern
                    import re
                    version_match = re.search(r'[\\d.]+', server)
                    if version_match:
                        version = version_match.group()
                        product = server[:version_match.start()].rstrip('/ ')
                        if product and version:
                            fingerprints.append(Fingerprint(
                                product=product,
                                version=version,
                                evidence=f"Server header: {server}"
                            ))

            # Check powered-by header (e.g., "PHP/7.4.3")
            powered_by = service_info.get("powered_by", "")
            if powered_by:
                # Common formats: "PHP/7.4.3", "Express"
                parts = powered_by.split("/")
                if len(parts) >= 2:
                    product = parts[0].strip()
                    version = parts[1].split()[0].strip()
                    if version and any(c.isdigit() for c in version):
                        fingerprints.append(Fingerprint(
                            product=product,
                            version=version,
                            evidence=f"X-Powered-By header: {powered_by}"
                        ))
                elif powered_by and any(c.isdigit() for c in powered_by):
                    import re
                    version_match = re.search(r'[\\d.]+', powered_by)
                    if version_match:
                        version = version_match.group()
                        product = powered_by[:version_match.start()].rstrip()
                        if product and version:
                            fingerprints.append(Fingerprint(
                                product=product,
                                version=version,
                                evidence=f"X-Powered-By header: {powered_by}"
                            ))

            # If we have fingerprints, query the cve-index with CPE matching
            if fingerprints:
                try:
                    # Create settings for the cve-index query
                    settings = Settings(
                        requests_per_second=program.requests_per_second,
                        cve_index_url=program.cve_index_url,
                    )

                    # Use the enhanced CVE lookup with CPE matching
                    cve_candidates = await lookup(
                        fingerprints=fingerprints,
                        cve_index_url=program.cve_index_url,
                        timeout=15.0,
                        k=10
                    )

                    # Convert CveCandidate objects to dicts for compatibility
                    cve_results = []
                    for candidate in cve_candidates:
                        cve_results.append({
                            "id": candidate.cve_id,
                            "product": candidate.product,
                            "version": candidate.version,
                            "cvss_severity": candidate.cvss_severity,
                            "cvss_score": candidate.cvss_score,
                            "why": candidate.why,
                            "source": "cve-index"
                        })

                    if cve_results:
                        vulns.append({
                            "host": host,
                            "service": service_info,
                            "cves": cve_results,
                            "priority_score": lead.get("priority_score", 0)
                        })
                except Exception as e:
                    # Fallback to original text-based search if CPE lookup fails
                    try:
                        cve_results = await _search_cves_for_service(
                            client, program.cve_index_url, service_info
                        )
                        if cve_results:
                            vulns.append({
                                "host": host,
                                "service": service_info,
                                "cves": cve_results,
                                "priority_score": lead.get("priority_score", 0)
                            })
                    except Exception:
                        # Continue scanning other leads if one fails
                        continue
            else:
                # No fingerprints found, fall back to original text-based search
                try:
                    cve_results = await _search_cves_for_service(
                        client, program.cve_index_url, service_info
                    )
                    if cve_results:
                        vulns.append({
                            "host": host,
                            "service": service_info,
                            "cves": cve_results,
                            "priority_score": lead.get("priority_score", 0)
                        })
                except Exception:
                    # Continue scanning other leads if one fails
                    continue

    return vulns


async def _fingerprint_service(client: httpx.AsyncClient, host: str) -> dict | None:
    """Attempt to fingerprint service running on host."""
    # Try common web ports
    ports_to_try = [80, 443, 8080, 8443, 9999]

    for port in ports_to_try:
        scheme = "https" if port in [443, 8443] else "http"
        url = f"{scheme}://{host}:{port}"

        try:
            resp = await client.get(url, follow_redirects=True)
            # Extract useful headers for fingerprinting
            server = resp.headers.get("server", "").lower()
            powered_by = resp.headers.get("x-powered-by", "").lower()

            service_info = {
                "host": host,
                "port": port,
                "scheme": scheme,
                "server": server,
                "powered_by": powered_by,
                "status_code": resp.status_code
            }

            # Try to get more specific info from response body if small
            if len(resp.text) < 10000:  # Limit to avoid large responses
                service_info["title"] = _extract_title(resp.text)

            return service_info
        except Exception:
            # Try next port
            continue

    return None


def _extract_title(html: str) -> str:
    """Extract title tag from HTML."""
    import re
    match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
    return match.group(1).strip() if match else ""


async def _search_cves_for_service(client: httpx.AsyncClient, cve_index_url: str, service_info: dict) -> list[dict]:
    """Search CVE index for vulnerabilities matching service info."""
    # Build search query from service info
    query_parts = []

    if service_info.get("server"):
        query_parts.append(service_info["server"])
    if service_info.get("powered_by"):
        query_parts.append(service_info["powered_by"])
    if service_info.get("title"):
        query_parts.append(service_info["title"])

    if not query_parts:
        return []

    query = " ".join(query_parts)

    try:
        resp = await client.get(
            f"{cve_index_url.rstrip('/')}/search",
            params={"q": query, "k": 10}
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("results", [])
    except Exception:
        return []


_classifier = None


def classify(description: str) -> dict:
    """Classify a description via cve-classifier (loads the model once, cached).

    Sync + heavy (torch) — call from a thread worker. Raises ComponentMissing or
    a model/adapter error the UI can surface."""
    global _classifier
    try:
        from cve_classifier.config import get_settings
        from cve_classifier.infer import Classifier
    except ImportError as exc:
        raise ComponentMissing(
            "cve-classifier not installed. Run: pip install -e ../cve-classifier[train]"
        ) from exc
    if _classifier is None:
        _classifier = Classifier(get_settings())
    return _classifier.classify(description)


def render_batch_report(
    program_name: str,
    vulns: list[dict],
    out_dir: Path,
) -> Path:
    """
    Generate a consolidated Markdown and JSON report for a list of vulnerabilities.

    Parameters
    ----------
    program_name: str
        Name of the program (used for file naming and header).
    vulns: list[dict]
        Each dict is as returned by ``engine.scan_for_vulns`` (after scoring).
        Expected keys: ``host``, ``service`` (dict with ``host``, ``port``,
        ``scheme``, ``server``, ``powered_by``, ``status_code``, optional
        ``title``), ``cves`` (list of dicts with ``id``, ``cvss_vector``,
        ``cvss_score``, ``exploit_available``), ``priority_score``.
    out_dir: pathlib.Path
        Directory where the report files will be written. The function creates
        ``out_dir`` if it does not exist.

    Returns
    -------
    pathlib.Path
        Path to the generated Markdown report.
    """
    import json
    from datetime import datetime, timezone

    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # JSON report (machine‑readable)
    json_path = out_dir / f"{program_name}_report.json"
    json_data = {
        "program": program_name,
        "generated_at": timestamp,
        "count": len(vulns),
        "vulnerabilities": vulns,
    }
    json_path.write_text(json.dumps(json_data, indent=2), encoding="utf-8")

    # Markdown report (human‑readable)
    md_path = out_dir / f"{program_name}_report.md"
    lines = [
        f"# {program_name} – Vulnerability Scan Report",
        "",
        f"*Generated on {timestamp}*",
        "",
        f"## Summary",
        f"- Total findings: {len(vulns)}",
        "",
        "## Findings (sorted by priority)",
        "",
    ]

    # Build a table header
    lines.append("| Score | Host:Port | Service | CVEs | Details |")
    lines.append("|-------|-----------|---------|------|---------|")
    for v in sorted(vulns, key=lambda x: x.get("priority_score", 0), reverse=True):
        score = v.get("priority_score", 0)
        svc = v.get("service", {})
        host = svc.get("host", "")
        port = svc.get("port", "")
        scheme = svc.get("scheme", "")
        hostport = f"{host}:{port}" if port else host
        service_str = f"{scheme.upper()} {svc.get('server','')} {svc.get('powered_by','')}".strip()
        cves = v.get("cves", [])
        cve_list = ", ".join(
            f"{c.get('id','?')} ({c.get('cvss_score','?')})" for c in cves
        ) or "none"
        # Provide a link‑like placeholder for details (we could use HTML details, but plain text works)
        details = "view"
        lines.append(
            f"| {score} | {hostport} | {service_str} | {cve_list} | {details} |"
        )
    lines.append("")
    lines.append("## Detailed Findings")
    lines.append("")

    for idx, v in enumerate(sorted(vulns, key=lambda x: x.get("priority_score", 0), reverse=True), start=1):
        svc = v.get("service", {})
        host = svc.get("host", "")
        port = svc.get("port", "")
        scheme = svc.get("scheme", "")
        lines.append(f"### {idx}. {host}:{port} ({scheme.upper()})")
        lines.append("")
        lines.append(f"**Priority Score:** {v.get('priority_score', 0)}")
        lines.append("")
        lines.append("**Service Information:**")
        lines.append(f"- Host: {host}")
        lines.append(f"- Port: {port}")
        lines.append(f"- Scheme: {scheme}")
        lines.append(f"- Server: {svc.get('server', 'unknown')}")
        lines.append(f"- Powered‑by: {svc.get('powered_by', 'unknown')}")
        lines.append(f"- Status Code: {svc.get('status_code', 'unknown')}")
        title = svc.get("title")
        if title:
            lines.append(f"- HTML Title: {title}")
        lines.append("")
        lines.append("**CVEs:**")
        if not v.get("cves"):
            lines.append("- None")
        else:
            for c in v.get("cves", []):
                cid = c.get("id", "UNKNOWN")
                cvec = c.get("cvss_vector", "N/A")
                cscore = c.get("cvss_score", "N/A")
                exploit = "✓" if c.get("exploit_available") else "✗"
                lines.append(
                    f"- {cid} (CVSS: {cvec} → {cscore}) [{exploit}]"
                )
        lines.append("")
        lines.append("**Suggested PoC Skeleton (fill in `{{PAYLOAD}}`):**")
        if scheme == "https" or scheme == "http":
            base_url = f"{scheme}://{host}:{port}"
            lines.append("```bash")
            lines.append(f"curl -v '{base_url}/{{PAYLOAD}}'")
            lines.append("```")
        else:
            lines.append("_No HTTP/HTTPS service detected – manual investigation required._")
        lines.append("")
        lines.append("---")
        lines.append("")

    md_path.write_text("\n".join(lines), encoding="utf-8")
    return md_path
