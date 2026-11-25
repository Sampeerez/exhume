"""Tests for value-based deduplication (models.group_findings) and its effect on reports."""
from __future__ import annotations

from exhume.models import FileResult, Finding, ScanStats, Severity, Verified, group_findings, group_sort_key
from exhume.reporting.console import print_report
from exhume.reporting.json_report import build_payload


def _finding(path, line, value="hunter2hunter2!!", detector="Credential assignment"):
    return Finding(detector=detector, severity=Severity.HIGH, line=line,
                   redacted="hu...!!", context=f"password={value}", path=path, secret=value)


def _repeated_results(n=30):
    results = []
    for i in range(n):
        f = _finding(f"share/file{i}.txt", 3)
        results.append(FileResult(path=f"share/file{i}.txt", name=f"file{i}.txt", ext=".txt",
                                  size=10, findings=[f]))
    # One file also has a DIFFERENT secret, which must stay a separate group.
    other = _finding("share/other.txt", 1, value="totally-different-secret")
    results.append(FileResult(path="share/other.txt", name="other.txt", ext=".txt", size=10,
                              findings=[other]))
    return results


def test_group_findings_collapses_same_value():
    results = _repeated_results(30)
    findings = [f for r in results for f in r.findings]
    groups = group_findings(findings)
    assert len(groups) == 2
    repeated = next(g for g in groups if g.rep.secret == "hunter2hunter2!!")
    assert repeated.count == 30
    assert len(repeated.locations) == 30
    assert repeated.locations[0] == ("share/file0.txt", 3, 0)


def test_group_sort_key_prefers_more_locations_within_same_severity():
    results = _repeated_results(5)
    findings = [f for r in results for f in r.findings]
    groups = sorted(group_findings(findings), key=group_sort_key)
    assert groups[0].count == 5   # the widely-repeated secret sorts before the one-off


def test_build_payload_dedupes_and_counts_occurrences():
    results = _repeated_results(30)
    payload = build_payload(results, ScanStats(root="/x", seen=31, scanned=31))
    assert payload["summary"]["total_findings"] == 2
    assert payload["summary"]["total_occurrences"] == 31
    rep = next(h for h in payload["findings"] if h["value"] == "hunter2hunter2!!")
    assert rep["occurrences"] == 30
    assert len(rep["locations"]) == 30
    assert rep["locations_truncated"] == 0


def test_console_report_shows_unique_count_not_every_occurrence(capsys):
    from exhume.config import Config
    results = _repeated_results(30)
    print_report(results, ScanStats(root="/x"), Config(verify=False))
    out = capsys.readouterr().out
    assert "more location(s)" in out
    # The value itself should be printed once per shown row, not 30 times.
    assert out.count("hunter2hunter2!!") < 10


def test_verified_live_counts_unique_values(tmp_path):
    from exhume.config import Config
    from exhume.scanner import Scanner
    (tmp_path / "a.txt").write_text("token=SAME-LIVE-SECRET-VALUE")
    (tmp_path / "b.txt").write_text("token=SAME-LIVE-SECRET-VALUE")
    cfg = Config(target=str(tmp_path), use_processes=False, autoinstall=False, verify=False, ai=False)
    scanner = Scanner(cfg)
    results = scanner.run()
    for r in results:
        for f in r.findings:
            f.verified = Verified.LIVE
    scanner.stats.verified_live = len({f.value_fingerprint() for r in results for f in r.findings
                                       if f.verified is Verified.LIVE})
    assert scanner.stats.verified_live == 1
