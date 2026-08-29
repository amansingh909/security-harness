"""Orchestrate: Finding -> {fingerprint, cvss, markdown, hackerone, bugcrowd}."""
from __future__ import annotations

import logging
from dataclasses import dataclass

from . import bugcrowd, hackerone, markdown_report
from .cvss import CvssError, base_score, qualitative_rating
from .dedup import fingerprint
from .models import Finding

log = logging.getLogger(__name__)


@dataclass
class GeneratedReport:
    fingerprint: str
    cvss_score: float | None
    rating: str
    cwe: str | None
    markdown: str
    hackerone: dict
    bugcrowd: dict


def generate(finding: Finding) -> GeneratedReport:
    cvss_score: float | None = None
    rating = "UNRATED"
    if finding.cvss_vector:
        try:
            cvss_score = base_score(finding.cvss_vector)
            rating = qualitative_rating(cvss_score)
        except CvssError as exc:
            log.warning("invalid cvss vector; leaving unrated",
                        extra={"vector": finding.cvss_vector, "error": str(exc)})

    cwe = finding.cwe
    markdown = markdown_report.render(finding, cvss_score, rating, cwe)
    report = GeneratedReport(
        fingerprint=fingerprint(finding),
        cvss_score=cvss_score,
        rating=rating,
        cwe=cwe,
        markdown=markdown,
        hackerone=hackerone.to_submission(finding, markdown, rating, cvss_score, cwe),
        bugcrowd=bugcrowd.to_submission(finding, markdown, rating, cwe),
    )
    log.info("generated report",
             extra={"fingerprint": report.fingerprint, "rating": rating,
                    "cvss": cvss_score, "program": finding.program})
    return report
