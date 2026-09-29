"""Async HTTP prober: pooled, rate-limited, retry-with-backoff. Sends only
GET/HEAD to observe live hosts — no payloads, no injected parameters."""
from __future__ import annotations

import asyncio
import logging
import random
import re
import socket

from .config import Settings
from .fingerprint import fingerprint
from .models import HostProbe
from .ratelimit import TokenBucket

log = logging.getLogger(__name__)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


_DNS_MARKERS = (
    "name or service not known",
    "nodename nor servname provided",
    "temporary failure in name resolution",
    "no address associated with hostname",
    "name does not resolve",
    "getaddrinfo failed",
)


def _is_dns_failure(exc: BaseException) -> bool:
    """True if this exception is a name-resolution failure.

    Retrying these is pointless — the hostname will not start existing between
    attempts — and each retry ladder costs ~7s per scheme.
    """
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, socket.gaierror):
            return True
        text = str(exc).lower()
        if any(marker in text for marker in _DNS_MARKERS):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def _extract_title(body: str) -> str | None:
    m = _TITLE_RE.search(body)
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] or None


class HttpProber:
    def __init__(self, settings: Settings, bucket: TokenBucket) -> None:
        import httpx

        self._s = settings
        self._bucket = bucket
        limits = httpx.Limits(
            max_connections=settings.max_concurrency,
            max_keepalive_connections=settings.max_concurrency,
        )
        timeout = httpx.Timeout(settings.http_timeout, connect=settings.connect_timeout)
        # Extra headers (e.g. a Vercel protection-bypass token) go on every
        # request the prober makes — passive probes and the built-in tester.
        headers = {"User-Agent": settings.user_agent}
        headers.update(settings.extra_request_headers or {})
        self._client = httpx.AsyncClient(
            headers=headers,
            timeout=timeout,
            limits=limits,
            verify=settings.verify_tls,
            follow_redirects=True,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def send(self, request):
        """Send an arbitrary request through the shared rate limiter.

        Active testing needs to issue custom requests but must not bypass the
        token bucket — the politeness guarantee applies to every request, not
        just the passive probes.
        """
        await self._bucket.acquire()
        return await self._client.send(request)

    async def probe(self, host: str) -> HostProbe:
        import httpx

        for scheme, port in (("https", 443), ("http", 80)):
            url = f"{scheme}://{host}"
            attempt = 0
            while True:
                attempt += 1
                await self._bucket.acquire()
                try:
                    resp = await self._client.get(url)
                    headers = {k: v for k, v in resp.headers.items()}
                    title = _extract_title(resp.text) if resp.text else None
                    return HostProbe(
                        host=host,
                        url=str(resp.url),
                        status=resp.status_code,
                        title=title,
                        server=headers.get("server") or headers.get("Server"),
                        port=port,
                        headers=headers,
                        fingerprints=fingerprint(headers, title),
                    )
                except (httpx.TransportError, httpx.HTTPError) as exc:
                    # A name that does not resolve will not resolve on retry.
                    # Backing off 1s/2s/4s per scheme on NXDOMAIN cost ~15s per
                    # dead seed host for nothing, so give up on this scheme now.
                    if _is_dns_failure(exc):
                        log.info("host does not resolve; skipping scheme",
                                 extra={"host": host, "scheme": scheme})
                        break
                    if attempt > self._s.max_retries:
                        log.info("probe failed on scheme; trying next",
                                 extra={"host": host, "scheme": scheme,
                                        "error": str(exc)})
                        break
                    delay = min(self._s.backoff_max,
                                self._s.backoff_base * (2 ** (attempt - 1)))
                    delay += random.uniform(0, delay * 0.25)
                    await asyncio.sleep(delay)
        return HostProbe(host=host, error="unreachable over http/https")
