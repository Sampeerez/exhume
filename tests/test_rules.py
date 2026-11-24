"""Tests de reglas personalizadas y allowlist."""
from __future__ import annotations

import json

from exhume.detectors import scan_text
from exhume.detectors.rules import load_allowlist, load_custom_detectors


def _write(tmp_path, data, name="rules.json"):
    p = tmp_path / name
    p.write_text(json.dumps(data))
    return str(p)


def test_custom_detector_matches(tmp_path):
    path = _write(tmp_path, {"rules": [
        {"name": "Clave ACME", "regex": "ACME-[0-9A-F]{8}", "severity": "critical", "anchors": ["acme-"]}
    ]})
    dets = load_custom_detectors([path])
    assert len(dets) == 1
    findings = scan_text("token ACME-DEADBEEF here", 3.8, extra_detectors=tuple(dets))
    assert any(f.detector == "Clave ACME" for f in findings)


def test_invalid_regex_skipped(tmp_path):
    path = _write(tmp_path, {"rules": [{"name": "mala", "regex": "("}]})
    assert load_custom_detectors([path]) == []


def test_allowlist_suppresses(tmp_path):
    path = _write(tmp_path, {"allowlist": ["EXAMPLE"]})
    allow = load_allowlist([path], "")
    # The line contains EXAMPLE => the whole line is ignored
    findings = scan_text("AKIAIOSFODNN7EXAMPLE", 3.8, allow=allow)
    assert findings == []


def test_no_builtin_only_custom(tmp_path):
    path = _write(tmp_path, {"rules": [{"name": "X", "regex": "ZZZ-\\d+"}]})
    dets = load_custom_detectors([path])
    # Con use_builtin=False, un AWS key NO debe detectarse
    findings = scan_text("AKIAIOSFODNN7EXAMPLE ZZZ-123", 3.8,
                         extra_detectors=tuple(dets), use_builtin=False)
    names = {f.detector for f in findings}
    assert "X" in names
    assert "AWS Access Key ID" not in names
