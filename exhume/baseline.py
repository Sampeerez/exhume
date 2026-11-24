"""Baseline support for re-audits.

A baseline is a JSON file with the fingerprints of previously-seen findings.
On a later scan, known findings are suppressed so the operator only reviews
what is NEW — the same workflow Gitleaks offers for CI.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .models import FileResult


def load_fingerprints(path: str) -> set[str]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return set()
    return set(data.get("fingerprints", []))


def write_fingerprints(path: str, results: list[FileResult]) -> int:
    fps = sorted({f.fingerprint() for r in results for f in r.findings})
    doc = {
        "tool": "exhume",
        "generated": datetime.now(timezone.utc).isoformat(),
        "fingerprints": fps,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return len(fps)


def suppress_known(results: list[FileResult], known: set[str]) -> int:
    """Remove findings whose fingerprint is in *known*. Returns how many were removed."""
    removed = 0
    for r in results:
        if not r.findings:
            continue
        kept = [f for f in r.findings if f.fingerprint() not in known]
        removed += len(r.findings) - len(kept)
        r.findings = kept
    return removed
