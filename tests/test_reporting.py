"""Tests for report generation."""
from __future__ import annotations

import json

from exhume.models import FileResult, Finding, ScanStats, Severity, Verified
from exhume.reporting.csv_report import write_csv
from exhume.reporting.html import write_html
from exhume.reporting.json_report import build_payload, human_size, write_json
from exhume.reporting.sarif import write_sarif


def _sample_results():
    f = Finding(detector="AWS Access Key ID", severity=Severity.CRITICAL, line=1,
                redacted="AKIA...MPLE", context="KEY=AKIA...MPLE", path="a.env",
                verified=Verified.LIVE, detail="account 123")
    r = FileResult(path="a.env", name="a.env", ext=".env", size=50,
                   tags=["config", "sensitive_name"], findings=[f])
    return [r]


def _stats():
    return ScanStats(root="/x", seen=1, scanned=1, verified_live=1)


def test_human_size():
    assert human_size(0) == "0.0B"
    assert human_size(1024) == "1.0KB"
    assert human_size(1024 * 1024) == "1.0MB"


def test_build_payload_structure():
    payload = build_payload(_sample_results(), _stats())
    assert payload["summary"]["total_findings"] == 1
    assert payload["summary"]["verified_live"] == 1
    assert payload["meta"]["tool"] == "exhume"
    assert "secret" not in payload["findings"][0]
    assert payload["findings"][0]["value"] == "AKIA...MPLE"


def test_write_json(tmp_path):
    p = tmp_path / "r.json"
    write_json(build_payload(_sample_results(), _stats()), str(p))
    data = json.loads(p.read_text())
    assert data["findings"][0]["verified"] == "live"


def test_write_csv(tmp_path):
    p = tmp_path / "r.csv"
    write_csv(build_payload(_sample_results(), _stats()), str(p))
    content = p.read_text()
    assert "severity" in content
    assert "LIVE" in content


def test_write_sarif(tmp_path):
    p = tmp_path / "r.sarif"
    write_sarif(build_payload(_sample_results(), _stats()), str(p))
    data = json.loads(p.read_text())
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"][0]["level"] == "error"


def test_print_report_runs(capsys):
    from exhume.config import Config
    from exhume.reporting import print_report
    cfg = Config(verify=True)
    print_report(_sample_results(), _stats(), cfg)
    out = capsys.readouterr().out
    assert "Exhume" in out
    assert "AWS Access Key ID" in out
    assert "LIVE" in out


def test_print_report_only_verified(capsys):
    from exhume.config import Config
    from exhume.reporting import print_report
    results = _sample_results()
    results[0].findings[0].verified = Verified.DEAD
    cfg = Config(verify=True, only_verified=True)
    print_report(results, _stats(), cfg)
    out = capsys.readouterr().out
    assert "No verified findings" in out


def test_write_html_safe_embedding(tmp_path):
    results = _sample_results()
    results[0].findings[0].context = "<script>alert(1)</script>"
    p = tmp_path / "r.html"
    write_html(build_payload(results, _stats()), str(p))
    html = p.read_text()
    # The data is embedded as JSON with </ neutralized, so no tag breakout survives.
    assert "</script>alert" not in html
    assert "<\\/script>" in html


def test_html_shows_real_value_by_default(tmp_path):
    from exhume.models import FileResult, Finding, Severity
    f = Finding(detector="GitHub token", severity=Severity.CRITICAL, line=1,
                redacted="ghp_...cd", context="token=ghp_REALSECRET", path="a.txt",
                secret="ghp_REALSECRET")
    payload = build_payload([FileResult(path="a.txt", name="a.txt", ext=".txt", size=9, findings=[f])],
                            _stats(), mask=False)
    assert payload["findings"][0]["value"] == "ghp_REALSECRET"
    masked = build_payload([FileResult(path="a.txt", name="a.txt", ext=".txt", size=9, findings=[f])],
                           _stats(), mask=True)
    assert masked["findings"][0]["value"] == "ghp_...cd"
    assert "ghp_REALSECRET" not in str(masked)


def test_html_truncates_to_max_and_reports_omitted(tmp_path):
    payload = build_payload(_sample_results(), _stats())
    payload["findings"] = payload["findings"] * 30
    p = tmp_path / "r.html"
    omitted = write_html(payload, str(p), max_findings=10)
    assert omitted == len(payload["findings"]) - 10
    assert "highest-severity unique values" in p.read_text()
    assert write_html(payload, str(p), max_findings=0) == 0


def test_html_has_report_mode_and_dismiss(tmp_path):
    p = tmp_path / "r.html"
    write_html(build_payload(_sample_results(), _stats()), str(p))
    html = p.read_text()
    assert "toggleReport" in html and "setDis" in html and "exhume-dismissed" in html
