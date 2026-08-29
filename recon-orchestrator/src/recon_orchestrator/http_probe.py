"""Async HTTP prober: pooled, rate-limited, retry-with-backoff. Sends only
GET/HEAD to observe live hosts — no payloads, no injected parameters."""
from __future__ import annotations

import asyncio
import logging
import random
import re

from .config import Settings
from .fingerprint import fingerprint
from .models import HostProbe
from .ratelimit import TokenBucket

log = logging.getLogger(__name__)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


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
        self._client = httpx.AsyncClient(
            headers={"User-Agent": settings.user_agent},
            timeout=timeout,
            limits=limits,
            verify=settings.verify_tls,
            follow_redirects=True,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

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
