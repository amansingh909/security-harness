"""Scope guard. Decides whether a host is authorized for testing, encoding the
scope-check discipline: exclusions beat includes, a bare apex is not a wildcard,
the ``a.example.com.evil.com`` bypass is rejected, and ambiguity yields
UNCERTAIN (which the orchestrator treats as 'do not touch'), never a guessed yes.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse

IN = "in"
OUT = "out"
UNCERTAIN = "uncertain"


@dataclass(frozen=True)
class Verdict:
    status: str  # IN | OUT | UNCERTAIN
    reason: str  # the exact rule (or absence) that decided it


def normalize_host(target: str) -> str:
    """Extract a bare lowercase hostname from a host or URL, dropping port."""
    value = target.strip().lower()
    if "//" in value or "/" in value:
        parsed = urlparse(value if "//" in value else f"//{value}")
        value = parsed.hostname or parsed.path.split("/")[0]
    if value.startswith("[") and "]" in value:  # bracketed IPv6
        return value[1 : value.index("]")]
    return value.split(":")[0]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _cidr_match(host: str, pattern: str) -> bool:
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return False


def _host_match(host: str, pattern: str) -> tuple[bool, int]:
    """Return (matched, subdomain_label_depth). depth 0 == exact match."""
    pattern = pattern.strip().lower()
    if pattern.startswith("*."):
        base = pattern[2:]
        suffix = "." + base
        if host.endswith(suffix) and host != base:
            depth = host[: -len(suffix)].count(".") + 1
            return True, depth
        return False, 0
    return (host == pattern), 0


class ScopeGuard:
    def __init__(
        self,
        in_scope: list[str],
        out_of_scope: list[str] | None = None,
        allow_multilevel_wildcard: bool = True,
    ) -> None:
        self.in_scope = [p.strip().lower() for p in in_scope if p.strip()]
        self.out_of_scope = [p.strip().lower() for p in (out_of_scope or []) if p.strip()]
        self.allow_multilevel_wildcard = allow_multilevel_wildcard

    def verdict(self, target: str) -> Verdict:
        host = normalize_host(target)
        if not host:
            return Verdict(OUT, "empty host")
        if not self.in_scope:
            return Verdict(OUT, "no in-scope entries configured")

        # 1) Exclusions win outright.
        for pattern in self.out_of_scope:
            matched, _ = self._match(host, pattern)
            if matched:
                return Verdict(OUT, f"matches out-of-scope entry '{pattern}'")

        # 2) Includes. Prefer a clean IN; downgrade deep-wildcard to UNCERTAIN.
        best: Verdict | None = None
        for pattern in self.in_scope:
            matched, depth = self._match(host, pattern)
            if not matched:
                continue
            is_wildcard = pattern.startswith("*.")
            if is_wildcard and depth > 1 and not self.allow_multilevel_wildcard:
                best = best or Verdict(
                    UNCERTAIN,
                    f"multi-level subdomain under wildcard '{pattern}'; "
                    "confirm the program covers nested subdomains",
                )
                continue
            return Verdict(IN, f"matches in-scope entry '{pattern}'")

        return best or Verdict(OUT, "matches no in-scope entry")

    def _match(self, host: str, pattern: str) -> tuple[bool, int]:
        if "/" in pattern:  # CIDR
            return (_cidr_match(host, pattern) if _is_ip(host) else False), 0
        return _host_match(host, pattern)

    def is_authorized(self, target: str) -> bool:
        """The orchestrator's gate: only a clean IN verdict may be probed."""
        return self.verdict(target).status == IN
