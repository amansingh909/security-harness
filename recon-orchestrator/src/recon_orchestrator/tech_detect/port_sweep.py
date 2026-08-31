"""Lightweight port sweep and service fingerprinting.

Performs GET/HEAD requests on a list of hosts and ports to discover
additional services and fingerprint them via headers/title.
All requests are scoped to the target host and use only GET/HEAD (no payloads).
"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Set

import httpx

from ..config import Settings
from ..fingerprint import fingerprint
from ..models import Fingerprint, HostProbe
from ..ratelimit import TokenBucket

log = logging.getLogger(__name__)

# Default list of ports to scan beyond the standard web ports.
# These are common service ports that often reveal interesting attack surface.
_DEFAULT_TECH_PORTS: Set[int] = {
    22,    # SSH
    25,    # SMTP
    110,   # POP3
    143,   # IMAP
    389,   # LDAP
    445,   # SMB
    993,   # IMAPS
    995,   # POP3S
    1433,  # MSSQL
    1521,  # Oracle DB
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8000,  # Common alt-http
    8001,  # Common alt-http
    8080,  # Already in default web ports but we keep for completeness
    8081,  # Common alt-http
    8443,  # Already in default web ports
    8888,  # Common alt-http
    9000,  # Common alt-http
    9090,  # Common alt-http
    9200,  # Elasticsearch
    9300,  # Elasticsearch transport
    27017, # MongoDB
}


class TechProber:
    """Probe a host on a list of ports using GET/HEAD requests.

    Similar to HttpProber but works on an arbitrary list of ports.
    Uses the same Settings for timeouts, retries, and rate limiting.
    """

    def __init__(self, settings: Settings, ports: Set[int] | None = None) -> None:
        self._s = settings
        self._ports = ports if ports is not None else _DEFAULT_TECH_PORTS
        # We'll use a separate TokenBucket for this prober so it doesn't interfere
        # with the main recon prober if they run concurrently.
        self._bucket = TokenBucket(self._s.requests_per_second)

        # Build the httpx client with limits and timeout.
        limits = httpx.Limits(
            max_connections=self._s.max_concurrency,
            max_keepalive_connections=self._s.max_concurrency,
        )
        timeout = httpx.Timeout(self._s.http_timeout, connect=self._s.connect_timeout)
        self._client = httpx.AsyncClient(
            headers={"User-Agent": self._s.user_agent},
            timeout=timeout,
            limits=limits,
            verify=self._s.verify_tls,
            follow_redirects=True,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def probe_host(self, host: str) -> List[HostProbe]:
        """Probe the given host on all configured ports.

        Returns a list of HostProbe objects for ports that responded successfully.
        """
        results: List[HostProbe] = []
        for port in self._ports:
            # Determine scheme: HTTPS for port 443, otherwise HTTP.
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{host}:{port}"
            attempt = 0
            while True:
                attempt += 1
                await self._bucket.acquire()
                try:
                    resp = await self._client.get(url)
                    headers = {k: v for k, v in resp.headers.items()}
                    # Extract title from HTML if present and small.
                    title: str | None = None
                    if resp.text and len(resp.text) < 10000:  # Avoid huge responses
                        # Simple regex for title tag.
                        import re
                        match = re.search(r"<title[^>]*>([^<]+)</title>", resp.text, re.IGNORECASE)
                        if match:
                            title = match.group(1).strip()
                    # Derive fingerprints from headers and title.
                    fps = fingerprint(headers, title)
                    results.append(
                        HostProbe(
                            host=host,
                            url=str(resp.url),
                            status=resp.status_code,
                            title=title,
                            server=headers.get("server") or headers.get("Server"),
                            port=port,
                            headers=headers,
                            fingerprints=fps,
                        )
                    )
                    break  # Success, move to next port
                except (httpx.TransportError, httpx.HTTPError) as exc:
                    if attempt > self._s.max_retries:
                        log.debug(
                            "Port probe failed after retries",
                            extra={"host": host, "port": port, "scheme": scheme, "error": str(exc)},
                        )
                        break  # Give up on this port
                    # Exponential backoff with jitter
                    delay = min(
                        self._s.backoff_max,
                        self._s.backoff_base * (2 ** (attempt - 1)),
                    )
                    delay += delay * 0.25 * (hash(f"{host}{port}{attempt}") % 1000) / 1000.0  # Simple jitter
                    await asyncio.sleep(delay)
                except Exception as exc:  # Catch-all to avoid crashing the whole sweep
                    log.warning(
                        "Unexpected error during port probe",
                        extra={"host": host, "port": port, "error": str(exc)},
                    )
                    break
        return results


async def sweep_ports(
    hosts: List[str],
    settings: Settings,
    ports: Set[int] | None = None,
) -> List[HostProbe]:
    """Convenience function to sweep a list of hosts for open ports and fingerprints.

    Returns a flat list of HostProbe objects from all hosts.
    """
    prober = TechProber(settings, ports)
    try:
        all_results: List[HostProbe] = []
        for host in hosts:
            results = await prober.probe_host(host)
            all_results.extend(results)
        return all_results
    finally:
        await prober.aclose()