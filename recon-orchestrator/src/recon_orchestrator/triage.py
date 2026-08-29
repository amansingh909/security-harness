"""Rank probed hosts by how much they deserve manual attention, using the
recon-triage rubric applied only to signals present in the collected data.
Output is *priority*, never a vulnerability claim."""
from __future__ import annotations

import re

from .models import CandidateFinding, HostProbe

_NONPROD = ("dev", "staging", "stage", "uat", "test", "qa", "internal", "sandbox", "preprod")
_ADMIN = ("admin", "jenkins", "grafana", "kibana", "jira", "vpn", "phpmyadmin",
          "gitlab", "portal", "dashboard", "manage")
_DEFAULT_TITLES = ("welcome to nginx", "apache2 ubuntu default page", "iis windows server",
                   "it works", "test page for the apache")
_STANDARD_PORTS = {80, 443}


def _host_labels(host: str) -> list[str]:
    return re.split(r"[.\-_]", host.lower())


def score_host(probe: HostProbe) -> CandidateFinding:
    signals: list[str] = []
    score = 0
    labels = _host_labels(probe.host)

    for kw in _NONPROD:
        if kw in labels:
            score += 3
            signals.append(f"non-prod naming ('{kw}') — weaker auth / debug surface")
            break
    for kw in _ADMIN:
        if kw in labels:
            score += 4
            signals.append(f"admin/internal tooling ('{kw}') — high-value, often mis-scoped")
            break

    if probe.status in (401, 403):
        score += 2
        signals.append(f"auth boundary (HTTP {probe.status}) — worth probing access control")
    elif probe.status is not None and probe.status >= 500:
        score += 2
        signals.append(f"server error (HTTP {probe.status}) — possible error leakage")

    if probe.port not in _STANDARD_PORTS:
        score += 2
        signals.append(f"non-standard port ({probe.port}) — forgotten service?")

    if probe.title and probe.title.strip().lower() in _DEFAULT_TITLES:
        score += 2
        signals.append(f"default title ('{probe.title.strip()}') — unfinished/forgotten deploy")

    versioned = [f for f in probe.fingerprints if f.version]
    if versioned:
        score += 1
        for fp in versioned:
            signals.append(f"version disclosed ({fp.product} {fp.version}) — CVE surface")

    return CandidateFinding(
        host=probe.host,
        url=probe.url,
        priority_score=score,
        signals=signals,
        fingerprints=probe.fingerprints,
        status=probe.status,
    )


def triage(probes: list[HostProbe]) -> list[CandidateFinding]:
    """Return scored candidates with at least one signal, highest priority first.
    Hosts with no distinguishing signal are dropped — triage means focus."""
    candidates = [score_host(p) for p in probes if not p.error]
    interesting = [c for c in candidates if c.priority_score > 0]
    interesting.sort(key=lambda c: (-c.priority_score, c.host))
    return interesting
