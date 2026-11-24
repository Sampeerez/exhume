"""Integration tests for the scanner and reports."""
from __future__ import annotations

import os

from exhume import Scanner
from exhume.models import Verified
from exhume.reporting import write_outputs
from exhume.reporting.json_report import build_payload


def _make_tree(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / ".env").write_text(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "STRIPE=sk_" + "live_abcdef0123456789abcdef01\n"
    )
    (tmp_path / "app.js").write_text("const k='" + "AIza" + "SyA1234567890abcdefghijklmnopqrstuv';")
    (tmp_path / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----")
    (tmp_path / "photo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)


def test_end_to_end(tmp_path, cfg):
    _make_tree(tmp_path)
    cfg.target = str(tmp_path)
    results = Scanner(cfg).run()
    detectors = {f.detector for r in results for f in r.findings}
    assert "AWS Access Key ID" in detectors
    assert "Stripe secret key" in detectors
    assert "Google API key" in detectors
    assert any("key_material" in r.tags for r in results)


def test_reveal_default_and_mask(tmp_path, cfg):
    _make_tree(tmp_path)
    cfg.target = str(tmp_path)
    scanner = Scanner(cfg)
    results = scanner.run()
    # Default: real values are shown (report is for the pentester).
    revealed = build_payload(results, scanner.stats, mask=False)
    assert "AKIAIOSFODNN7EXAMPLE" in str(revealed)
    assert revealed["summary"]["total_findings"] > 0
    # --mask: client-safe, no plaintext secret anywhere.
    masked = build_payload(results, scanner.stats, mask=True)
    assert "AKIAIOSFODNN7EXAMPLE" not in str(masked)


def test_reports_written(tmp_path, cfg):
    _make_tree(tmp_path)
    cfg.target = str(tmp_path)
    cfg.output_prefix = str(tmp_path / "rep")
    cfg.want_html = cfg.want_json = cfg.want_csv = cfg.want_sarif = True
    scanner = Scanner(cfg)
    results = scanner.run()
    written = write_outputs(results, scanner.stats, cfg)
    for ext in (".html", ".json", ".csv", ".sarif"):
        match = [p for p in written if p.endswith(ext)]
        assert match and os.path.getsize(match[0]) > 0


def test_single_file_target(tmp_path, cfg):
    f = tmp_path / "creds.txt"
    f.write_text("token=ghp_" + "1234567890abcdefABCDEF1234567890abcd")
    cfg.target = str(f)
    results = Scanner(cfg).run()
    assert any(fi.detector == "GitHub token" for r in results for fi in r.findings)


def test_verify_marks_live(tmp_path, cfg, monkeypatch):
    from exhume import scanner as scanner_mod
    (tmp_path / "t.txt").write_text("ghp_" + "1234567890abcdefABCDEF1234567890abcd")
    cfg.target = str(tmp_path)
    cfg.verify = True
    monkeypatch.setattr(scanner_mod, "verify_single",
                        lambda key, secret: (Verified.LIVE, "GitHub user: tester"))
    results = Scanner(cfg).run()
    live = [f for r in results for f in r.findings if f.verified is Verified.LIVE]
    assert live and "tester" in (live[0].detail or "")


def test_exclude_glob(tmp_path, cfg):
    (tmp_path / "keep.env").write_text("AKIAIOSFODNN7EXAMPLE")
    (tmp_path / "skip.min.js").write_text("AKIAIOSFODNN7EXAMPLE")
    cfg.target = str(tmp_path)
    cfg.exclude = ["*.min.js"]
    results = Scanner(cfg).run()
    paths = [r.path for r in results for _ in r.findings]
    assert any("keep.env" in p for p in paths)
    assert not any("skip.min.js" in p for p in paths)


def test_baseline_suppresses_known(tmp_path, cfg):
    (tmp_path / "a.env").write_text("AKIAIOSFODNN7EXAMPLE")
    cfg.target = str(tmp_path)
    base = tmp_path / "baseline.json"
    cfg.write_baseline_file = str(base)
    first = Scanner(cfg).run()
    assert any(f for r in first for f in r.findings)
    # Second run with the baseline: the known finding is suppressed.
    cfg2 = cfg
    cfg2.write_baseline_file = ""
    cfg2.baseline_file = str(base)
    scanner = Scanner(cfg2)
    second = scanner.run()
    assert sum(len(r.findings) for r in second) == 0
    assert scanner.stats.suppressed >= 1


def test_coverage_counts(tmp_path, cfg):
    (tmp_path / "a.txt").write_text("hello")
    (tmp_path / "b.mp3").write_bytes(b"\x89PNG\r\n" + b"\x00" * 50)
    cfg.target = str(tmp_path)
    scanner = Scanner(cfg)
    scanner.run()
    assert scanner.stats.coverage.get("scanned") == 1
    assert scanner.stats.coverage.get("media_skipped") == 1
