"""Polish report prose with an LLM, guided by the "signs of AI writing" rules.

Runs the operator's ``freeclaude`` (free-token Claude Code) by default;
override with the ``HARNESS_HUMANIZER_CMD`` environment variable. It NEVER
touches evidence — callers pass only prose (summary / impact / remediation),
never reproduction steps, requests/responses, or CVSS. If the backend is
unavailable or errors, the original text is returned unchanged, so report
generation never breaks on a missing or slow model.
"""
from __future__ import annotations

import os
import subprocess

# Condensed from the humanizer skill (Wikipedia "signs of AI writing"). The
# instruction to preserve every fact is what keeps this a *prose* pass and not a
# second chance to fabricate.
_RULES = """\
Rewrite the text below so it reads as natural, human-written security prose.
Remove the signs of AI writing: inflated or promotional phrasing, the rule of
three, em-dash overuse, negative parallelisms ("it's not X, it's Y"), vague
attributions, filler ("it's important to note"), and AI-tell vocabulary (delve,
leverage, robust, seamless, underscore, testament, realm). Keep every technical
fact, number, identifier, and claim EXACTLY as written — do not add, remove, or
soften any factual content. Return only the rewritten text, nothing else.

TEXT:
"""


def _default_cmd() -> str:
    """The humanizer backend command: the operator's freeclaude if present."""
    local = os.path.expanduser("~/.local/bin/freeclaude")
    return local if os.path.exists(local) else "freeclaude"


def _run_backend(prompt: str, cmd: str, timeout: float) -> str:
    """Call the backend once in print mode and return its stdout (raises on failure)."""
    result = subprocess.run(
        [cmd, "-p", prompt],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(f"{cmd} exited {result.returncode}: {result.stderr[:200]}")
    return result.stdout.strip()


def humanize(text: str, *, cmd: str | None = None, timeout: float = 120.0) -> str:
    """Return a de-AI'd version of *prose*; the original text if the backend fails.

    Only ever pass prose here — never evidence fields (reproduction steps,
    request/response, CVSS). On any backend error the input is returned
    unchanged.
    """
    text = (text or "").strip()
    if not text:
        return text
    cmd = cmd or os.getenv("HARNESS_HUMANIZER_CMD") or _default_cmd()
    try:
        cleaned = _run_backend(_RULES + text, cmd, timeout)
    except (OSError, subprocess.SubprocessError, RuntimeError):
        return text
    return cleaned or text
