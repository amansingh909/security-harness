"""Regression tests for the probe retry paths.

A hostname that does not resolve will not resolve on retry, but the prober ran
the full backoff ladder anyway — 1s, 2s, 4s per scheme, ~15.7s per dead seed
host, measured. The port sweeper had a separate defect: `asyncio.sleep` in its
retry branch with `asyncio` never imported, a NameError raised inside an
`except` handler where the sibling handler below could not catch it.
"""
from __future__ import annotations

import asyncio
import socket

import httpx
import pytest

from recon_orchestrator.config import Settings
from recon_orchestrator.http_probe import HttpProber, _is_dns_failure
from recon_orchestrator.ratelimit import TokenBucket
from recon_orchestrator.tech_detect.port_sweep import TechProber


# --- the predicate -----------------------------------------------------------

@pytest.mark.parametrize("exc", [
    socket.gaierror(-2, "Name or service not known"),
    httpx.ConnectError("[Errno -2] Name or service not known"),
    httpx.ConnectError("nodename nor servname provided"),
])
def test_dns_failures_are_recognised(exc):
    assert _is_dns_failure(exc)


@pytest.mark.parametrize("exc", [
    httpx.ConnectTimeout("timed out"),
    httpx.ReadTimeout("slow"),
    httpx.ConnectError("Connection refused"),
])
def test_other_transport_errors_are_not_dns_failures(exc):
    """These are genuinely transient — they must keep their retries."""
    assert not _is_dns_failure(exc)


def test_dns_failure_is_found_through_a_cause_chain():
    inner = socket.gaierror(-2, "Name or service not known")
    outer = httpx.ConnectError("wrapped")
    outer.__cause__ = inner
    assert _is_dns_failure(outer)


# --- the probe paths ---------------------------------------------------------

@pytest.mark.asyncio
async def test_unresolvable_host_skips_the_backoff_ladder():
    """Both schemes give up immediately, so a dead seed costs ~0s not ~15s."""
    settings = Settings(requests_per_second=50.0, backoff_base=5.0, max_retries=3)
    prober = HttpProber(settings, TokenBucket(50.0))
    try:
        started = asyncio.get_running_loop().time()
        probe = await prober.probe("no-such-host-for-tests.invalid")
        elapsed = asyncio.get_running_loop().time() - started
    finally:
        await prober.aclose()

    assert probe.error
    # With backoff_base=5.0 the old code slept >=35s across both schemes.
    assert elapsed < 5.0, f"took {elapsed:.1f}s — the retry ladder still runs"


@pytest.mark.asyncio
async def test_port_sweep_retry_branch_does_not_raise_nameerror():
    """`await asyncio.sleep(delay)` sat in an except handler with asyncio
    unimported; the NameError escaped the sibling catch-all below it."""
    class AlwaysFails:
        async def get(self, *args, **kwargs):
            raise httpx.ConnectError("simulated transport error")

        async def aclose(self):
            pass

    settings = Settings(requests_per_second=50.0, max_retries=1,
                        backoff_base=0.01, backoff_max=0.02)
    prober = TechProber(settings, ports={80})
    await prober.aclose()
    prober._client = AlwaysFails()

    assert await prober.probe_host("example.com") == []
