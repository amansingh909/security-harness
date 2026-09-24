"""Prose humanizer: de-AI report wording, never touch evidence, never crash."""
from __future__ import annotations

from harness import humanizer


def test_humanize_returns_backend_output(monkeypatch):
    monkeypatch.setattr(humanizer, "_run_backend",
                        lambda prompt, cmd, timeout: "clean prose")
    assert humanizer.humanize("some AI-tinged text") == "clean prose"


def test_humanize_falls_back_to_original_when_backend_fails(monkeypatch):
    def boom(prompt, cmd, timeout):
        raise RuntimeError("backend down")
    monkeypatch.setattr(humanizer, "_run_backend", boom)
    original = "the original, untouched prose"
    assert humanizer.humanize(original) == original


def test_humanize_empty_text_never_calls_the_backend(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not call the backend for empty text")
    monkeypatch.setattr(humanizer, "_run_backend", boom)
    assert humanizer.humanize("   ") == ""


def test_humanize_sends_the_text_and_the_rules_to_the_backend(monkeypatch):
    seen = {}

    def capture(prompt, cmd, timeout):
        seen["prompt"] = prompt
        return "ok"
    monkeypatch.setattr(humanizer, "_run_backend", capture)
    humanizer.humanize("UNIQUE_INPUT_MARKER")
    assert "UNIQUE_INPUT_MARKER" in seen["prompt"]
    assert "human" in seen["prompt"].lower()  # the de-AI rules are included


def test_humanize_default_backend_is_freeclaude(monkeypatch):
    captured = {}

    class Done:
        returncode = 0
        stdout = "clean"
        stderr = ""

    def fake_run(argv, *a, **k):
        captured["argv"] = list(argv)
        return Done()
    monkeypatch.setattr(humanizer.subprocess, "run", fake_run)
    monkeypatch.delenv("HARNESS_HUMANIZER_CMD", raising=False)
    humanizer.humanize("text")
    assert "freeclaude" in captured["argv"][0]
    assert "-p" in captured["argv"]
