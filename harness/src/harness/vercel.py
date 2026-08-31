"""Resolve a Vercel preview deployment to a scoped host.

Two ways in:
  * a preview URL you paste (from the dashboard or the PR's Vercel comment)
  * a project name + VERCEL_TOKEN, which fetches the latest preview deployment

Either way the result is a single exact host (e.g.
``trazo-abc123-you.vercel.app``) — never ``*.vercel.app`` — so testing stays on
your own preview and never touches prod or anyone else's deployment.
"""
from __future__ import annotations

from urllib.parse import urlparse


def host_from_url(value: str) -> str | None:
    """Extract a host from a URL or a bare host string, else None."""
    value = value.strip()
    if not value:
        return None
    if "://" not in value:
        value = "https://" + value
    host = (urlparse(value).hostname or "").lower()
    # A real deployment host has a dot and no spaces.
    if not host or "." not in host or " " in host:
        return None
    return host


async def latest_preview_host(project: str, token: str, timeout: float = 20.0) -> str:
    """Return the host of the newest READY preview deployment for ``project``.

    Uses Vercel's REST API. Production deployments are excluded, so this can
    never point active testing at prod.
    """
    import httpx

    url = "https://api.vercel.com/v6/deployments"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"app": project, "limit": 20}
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.get(url, headers=headers, params=params)
    if resp.status_code == 401:
        raise PermissionError("Vercel rejected the token (401). Check VERCEL_TOKEN.")
    if resp.status_code != 200:
        raise RuntimeError(f"Vercel API {resp.status_code}: {resp.text[:200]}")

    deployments = resp.json().get("deployments", [])
    previews = [
        d for d in deployments
        if d.get("target") != "production" and d.get("state") in (None, "READY")
    ]
    if not previews:
        raise LookupError(
            f"no ready preview deployment found for project {project!r}"
        )
    # Vercel returns newest first; keep that order.
    dep_url = previews[0].get("url") or ""
    host = host_from_url(dep_url)
    if not host:
        raise LookupError(f"preview deployment had no usable url: {dep_url!r}")
    return host
