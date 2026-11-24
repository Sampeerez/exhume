"""Tests for the optional local-AI triage."""
from __future__ import annotations

import json

from exhume import ai
from exhume.models import FileResult, Finding, Severity, Verified


def _results():
    f = Finding(detector="AWS Access Key ID", severity=Severity.CRITICAL, line=1,
                redacted="AKIA...MPLE", context="KEY=AKIA...MPLE", path="a.env",
                verified=Verified.LIVE, secret="AKIAIOSFODNN7EXAMPLE")
    return [FileResult(path="a.env", name="a.env", ext=".env", size=10, findings=[f])]


def test_unreachable_returns_none():
    # Nothing listening on this port -> graceful None, no exception.
    assert ai.triage(_results(), "http://127.0.0.1:1", "") is None
    assert ai.available("http://127.0.0.1:1") == []


def test_prompt_is_masked_and_structured():
    prompt = ai._build_prompt(_results())
    assert "Executive summary" in prompt
    assert "AKIA...MPLE" in prompt          # masked value is used
    assert "AKIAIOSFODNN7EXAMPLE" not in prompt  # never the plaintext secret
    assert "VERIFIED-LIVE" in prompt


def test_triage_with_mocked_ollama(monkeypatch):
    def fake_available(url):
        return ["llama3.2"]

    def fake_post(url, body, timeout):
        return 200, json.dumps({"response": "## Executive summary\nOne live AWS key."}).encode()

    monkeypatch.setattr(ai, "available", fake_available)
    monkeypatch.setattr(ai, "_post", fake_post)
    res = ai.triage(_results(), "http://localhost:11434", "")
    assert res and res["model"] == "llama3.2"
    assert "Executive summary" in res["summary"]
