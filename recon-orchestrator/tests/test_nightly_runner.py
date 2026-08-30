"""Tests for the nightly runner: isolates per-program failure, merges a queue.

Uses a stubbed recon entrypoint so no network is touched.
"""
import pytest

from recon_orchestrator.nightly.runner import ProgramSpec, RunReport, run_nightly
from recon_orchestrator.nightly.scheduler import Schedule


@pytest.mark.asyncio
async def test_run_nightly_merges_all_programs(monkeypatch):
    captured = {}

    async def fake_run(settings, scope, seeds):
        # Return program-specific leads keyed by first seed.
        if any("acme.com" in seed for seed in seeds):
            return [{"host": "jenkins.acme.com", "priority_score": 8,
                     "signals": ["admin panel"], "url": None, "note": "u"}]
        return [{"host": "www.globex.com", "priority_score": 3,
                 "signals": [], "url": None, "note": "u"}]

    monkeypatch.setattr("recon_orchestrator.orchestrator.run_recon", fake_run)

    specs = {
        "acme": ProgramSpec(name="acme",
                            in_scope=["*.acme.com"], out_of_scope=[],
                            seeds=["jenkins.acme.com"]),
        "globex": ProgramSpec(name="globex",
                              in_scope=["*.globex.com"], out_of_scope=[],
                              seeds=["www.globex.com"]),
    }
    report = await run_nightly(Schedule(order=["acme", "globex"]), specs)
    assert set(report.ran) == {"acme", "globex"}
    assert report.failed == {}
    assert report.queue[0].host == "jenkins.acme.com"
    assert report.queue[0].program == "acme"


@pytest.mark.asyncio
async def test_run_nightly_isolates_program_failure(monkeypatch):
    async def fake_run(settings, scope, seeds):
        if "broken.com" in seeds:
            raise RuntimeError("scope misconfigured")
        return [{"host": "ok.com", "priority_score": 4, "signals": [], "note": "u"}]

    monkeypatch.setattr("recon_orchestrator.orchestrator.run_recon", fake_run)

    specs = {
        "broken": ProgramSpec(name="broken", in_scope=["*.broken.com"],
                              out_of_scope=[], seeds=["x.broken.com"]),
        "ok": ProgramSpec(name="ok", in_scope=["*.ok.com"],
                          out_of_scope=[], seeds=["ok.com"]),
    }
    report: RunReport = await run_nightly(Schedule(order=["broken", "ok"]), specs)
    assert report.ran == ["ok"]
    assert "broken" in report.failed
    assert len(report.queue) == 1
    assert report.queue[0].host == "ok.com"


@pytest.mark.asyncio
async def test_run_nightly_skips_programs_absent_from_specs(monkeypatch):
    async def fake_run(settings, scope, seeds):
        return []

    monkeypatch.setattr("recon_orchestrator.orchestrator.run_recon", fake_run)
    specs = {
        "acme": ProgramSpec(name="acme", in_scope=["*.acme.com"],
                            out_of_scope=[], seeds=["www.acme.com"]),
    }
    report = await run_nightly(Schedule(order=["acme", "ghost"]), specs)
    assert report.ran == ["acme"]
    assert "ghost" not in report.ran
