"""Glue between the TUI and the harness components.

Imports are lazy so the TUI still launches if a component isn't installed yet;
each function raises a clear, catchable error the UI can surface instead."""
from __future__ import annotations

from .programs import Program


class ComponentMissing(RuntimeError):
    """A required sibling component isn't importable/installed."""


async def run_recon(program: Program) -> list[dict]:
    """Run recon for a program via recon_orchestrator; return candidate leads."""
    try:
        from recon_orchestrator.config import Settings
        from recon_orchestrator.orchestrator import run_recon as _run
        from recon_orchestrator.scope import ScopeGuard
    except ImportError as exc:  # pragma: no cover - env dependent
        raise ComponentMissing(
            "recon-orchestrator not installed. Run: pip install -e ../recon-orchestrator"
        ) from exc

    seeds = list(program.seeds)
    if program.seeds_file:
        try:
            with open(program.seeds_file, encoding="utf-8") as fh:
                seeds += [
                    line.strip()
                    for line in fh
                    if line.strip() and not line.startswith("#")
                ]
        except OSError as exc:
            raise ComponentMissing(f"seeds_file unreadable: {exc}") from exc

    settings = Settings(
        requests_per_second=program.requests_per_second,
        cve_index_url=program.cve_index_url,
    )
    scope = ScopeGuard(
        program.in_scope, program.out_of_scope, program.allow_multilevel_wildcard
    )
    return await _run(settings, scope, seeds)


async def search_cve(query: str, cve_index_url: str, k: int = 10) -> list[dict]:
    """Query a running cve-index API for CVEs/techniques."""
    import httpx

    async with httpx.AsyncClient(base_url=cve_index_url, timeout=15) as client:
        resp = await client.get("/search", params={"q": query, "k": k})
        resp.raise_for_status()
        return resp.json().get("results", [])


def render_report(finding_path: str) -> dict:
    """Render a filled finding file to HackerOne/Bugcrowd/Markdown artifacts.

    Returns {"out_dir", "fingerprint", "rating", "cvss"}. Raises ComponentMissing
    if bounty-reporter isn't installed, or ValueError with the friendly
    missing-evidence message if the scaffold's required fields aren't filled."""
    import json
    from pathlib import Path

    import yaml

    try:
        from bounty_reporter.generator import generate
        from bounty_reporter.models import Finding
    except ImportError as exc:  # pragma: no cover - env dependent
        raise ComponentMissing(
            "bounty-reporter not installed. Run: pip install -e ../bounty-reporter"
        ) from exc

    from .findings import unfilled_todos

    data = yaml.safe_load(Path(finding_path).read_text(encoding="utf-8")) or {}
    data.pop("_recon_context", None)
    todos = unfilled_todos(data)
    if todos:
        raise ValueError(
            "still has TODO placeholders in: " + ", ".join(todos)
            + ". Fill them from your manual testing first."
        )
    finding = Finding.from_dict(data)
    report = generate(finding)

    out_dir = Path(finding_path).parent / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir / report.fingerprint
    base.with_suffix(".md").write_text(report.markdown, encoding="utf-8")
    (out_dir / f"{report.fingerprint}.hackerone.json").write_text(
        json.dumps(report.hackerone, indent=2), encoding="utf-8")
    (out_dir / f"{report.fingerprint}.bugcrowd.json").write_text(
        json.dumps(report.bugcrowd, indent=2), encoding="utf-8")
    return {
        "out_dir": str(out_dir),
        "fingerprint": report.fingerprint,
        "rating": report.rating,
        "cvss": report.cvss_score,
    }


def available() -> dict[str, bool]:
    """Which sibling components are importable in this environment."""
    import importlib.util

    def has(module: str) -> bool:
        try:
            return importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):
            return False

    return {
        "recon": has("recon_orchestrator"),
        "reporter": has("bounty_reporter"),
        # classifier inference needs both the package and the torch stack
        "classifier": has("cve_classifier") and has("torch"),
    }


async def cve_index_health(url: str) -> dict:
    """Ping a cve-index API's /health. Returns {up, vectors}."""
    import httpx

    try:
        async with httpx.AsyncClient(base_url=url, timeout=4) as client:
            resp = await client.get("/health")
            resp.raise_for_status()
            data = resp.json()
            return {"up": bool(data.get("elasticsearch")), "vectors": data.get("vectors")}
    except Exception:  # noqa: BLE001 - health check must never raise
        return {"up": False, "vectors": None}


_classifier = None


def classify(description: str) -> dict:
    """Classify a description via cve-classifier (loads the model once, cached).

    Sync + heavy (torch) — call from a thread worker. Raises ComponentMissing or
    a model/adapter error the UI can surface."""
    global _classifier
    try:
        from cve_classifier.config import get_settings
        from cve_classifier.infer import Classifier
    except ImportError as exc:
        raise ComponentMissing(
            "cve-classifier not installed. Run: pip install -e ../cve-classifier[train]"
        ) from exc
    if _classifier is None:
        _classifier = Classifier(get_settings())
    return _classifier.classify(description)
