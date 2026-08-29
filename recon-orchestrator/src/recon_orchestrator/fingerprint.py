"""Passive fingerprinting: derive (product, version) guesses from response
headers and title text only. Reasons strictly from data present — never asserts
software the response didn't reveal."""
from __future__ import annotations

import re

from .models import Fingerprint

# product/version token, e.g. "nginx/1.18.0", "Apache/2.4.49", "PHP/7.4.3"
_PROD_VER = re.compile(r"([A-Za-z][A-Za-z0-9_\-]+)/([0-9][0-9A-Za-z.\-]*)")
_GENERATOR = re.compile(r"([A-Za-z][A-Za-z0-9 ]+?)\s*v?([0-9][0-9.]*)")


def _add(out: list[Fingerprint], product: str, version: str | None, evidence: str) -> None:
    product = product.strip().lower()
    key = (product, version)
    if product and key not in {(f.product, f.version) for f in out}:
        out.append(Fingerprint(product=product, version=version, evidence=evidence))


def fingerprint(headers: dict[str, str], title: str | None = None) -> list[Fingerprint]:
    lower = {k.lower(): v for k, v in headers.items()}
    out: list[Fingerprint] = []

    for header in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        value = lower.get(header)
        if not value:
            continue
        matched = _PROD_VER.findall(value)
        if matched:
            for product, version in matched:
                _add(out, product, version, f"{header}: {value}")
        else:
            # Product named without a version, e.g. "Express".
            token = value.split()[0] if value.split() else value
            _add(out, token, None, f"{header}: {value}")

    generator = lower.get("x-generator")
    if generator:
        m = _GENERATOR.search(generator)
        if m:
            _add(out, m.group(1), m.group(2), f"x-generator: {generator}")

    if title:
        m = re.search(r"(WordPress|Drupal|Joomla)\s+([0-9][0-9.]*)", title, re.I)
        if m:
            _add(out, m.group(1), m.group(2), f"title: {title}")
    return out
