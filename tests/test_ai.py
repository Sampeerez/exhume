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


def test_prompt_dedupes_repeated_value_and_mentions_spread():
    f1 = Finding(detector="Credential assignment", severity=Severity.HIGH, line=1,
                redacted="hu...!!", context="password=hunter2hunter2!!", path="a.txt",
                secret="hunter2hunter2!!")
    f2 = Finding(detector="Credential assignment", severity=Severity.HIGH, line=1,
                redacted="hu...!!", context="password=hunter2hunter2!!", path="b.txt",
                secret="hunter2hunter2!!")
    results = [FileResult(path="a.txt", name="a.txt", ext=".txt", size=5, findings=[f1]),
              FileResult(path="b.txt", name="b.txt", ext=".txt", size=5, findings=[f2])]
    prompt = ai._build_prompt(results)
    assert prompt.count("hu...!!") == 1           # reported once, not once per occurrence
    assert "seen in 2 places" in prompt
    assert "2 occurrence" in prompt or "2 occurrence(s)" in prompt


def test_prompt_includes_sensitive_database_insight():
    r = FileResult(path="clientes.db", name="clientes.db", ext=".db", size=100, tags=["database"],
                  db_info={"tables": [{"name": "users", "rows": 3, "columns": ["email", "password"]}],
                          "sensitive_columns": ["users.email", "users.password"],
                          "ai_insight": "customer records with plaintext passwords"})
    prompt = ai._build_prompt([r])
    assert "customer records with plaintext passwords" in prompt
    assert "clientes.db" in prompt


def test_judge_db_insights_writes_one_sentence(monkeypatch):
    from exhume import ai_filter

    class FakeEngine:
        name = "fake"

        def generate(self, system, user, max_tokens=60):
            return "Customer PII with plaintext passwords — high risk.\n"

    r = FileResult(path="clientes.db", name="clientes.db", ext=".db", size=100, tags=["database"],
                  db_info={"tables": [{"name": "users", "rows": 3, "columns": ["email", "password"]}],
                          "sensitive_columns": ["users.email", "users.password"]})
    n = ai_filter.judge_db_insights([r], FakeEngine())
    assert n == 1
    assert r.db_info["ai_insight"] == "Customer PII with plaintext passwords — high risk."


def test_judge_db_insights_skips_non_sensitive_and_already_judged():
    from exhume import ai_filter

    class CountingEngine:
        name = "fake"
        calls = 0

        def generate(self, system, user, max_tokens=60):
            CountingEngine.calls += 1
            return "insight"

    plain = FileResult(path="lookup.db", name="lookup.db", ext=".db", size=10, tags=["database"],
                       db_info={"tables": [{"name": "codes", "rows": 3, "columns": ["id", "name"]}]})
    already = FileResult(path="x.db", name="x.db", ext=".db", size=10, tags=["database"],
                         db_info={"sensitive_columns": ["email"], "ai_insight": "already done"})
    n = ai_filter.judge_db_insights([plain, already], CountingEngine())
    assert n == 0
    assert CountingEngine.calls == 0


def test_no_findings_guard_overrides_hallucinated_section():
    results = []  # no FileResult at all -> definitely no findings
    hallucinated = ("## Executive summary\nSomething.\n\n"
                    "## Fastest paths to access\n- Made-up credential nobody reported.\n\n"
                    "## Recommended next steps\n- Do things.\n")
    fixed = ai._no_findings_guard(hallucinated, results)
    assert "Made-up credential" not in fixed
    assert "No credential findings." in fixed
    assert "## Recommended next steps" in fixed  # later sections survive untouched


def test_no_findings_guard_leaves_real_findings_alone():
    f = Finding(detector="GitHub token", severity=Severity.CRITICAL, line=1,
                redacted="ghp_...cd", context="x", path="a.txt", secret="ghp_REALSECRET")
    results = [FileResult(path="a.txt", name="a.txt", ext=".txt", size=5, findings=[f])]
    text = "## Fastest paths to access\n- The real GitHub token.\n"
    assert ai._no_findings_guard(text, results) == text
