"""Shared report payload builder and JSON output.

By default findings show the REAL secret values (the report is for the pentester).
Pass mask=True (CLI --mask) to produce a client-safe report with values redacted.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone

from .. import __version__
from ..models import FileResult, Finding, ScanStats, Severity, finding_sort_key


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def _mask_text(text: str, pairs: list[tuple[str, str]]) -> str:
    for secret, red in pairs:
        if secret and secret in text:
            text = text.replace(secret, red)
    return text


def _finding_dict(f: Finding, mask: bool, line_pairs: list[tuple[str, str]]) -> dict:
    if mask:
        value = f.redacted
        context = _mask_text(f.context, line_pairs)
        block = [[n, _mask_text(t, line_pairs)] for n, t in f.context_block]
    else:
        value = f.secret if f.secret is not None else f.redacted
        context = f.context
        block = [[n, t] for n, t in f.context_block]
    return {
        "detector": f.detector,
        "severity": int(f.severity),
        "severity_label": f.severity.label,
        "line": f.line,
        "col": f.col,
        "value": value,
        "masked_value": f.redacted,
        "context": context,
        "context_block": block,
        "path": f.path,
        "verified": f.verified.value,
        "detail": f.detail,
        "fingerprint": f.fingerprint(),
    }


def build_payload(results: list[FileResult], stats: ScanStats, mask: bool = False) -> dict:
    findings = sorted((f for r in results for f in r.findings), key=finding_sort_key)

    # Pairs per (path, line-vicinity) for masking the surrounding context blocks.
    pairs_by_path: dict[str, list[tuple[str, str]]] = defaultdict(list)
    if mask:
        for f in findings:
            if f.secret:
                pairs_by_path[f.path].append((f.secret, f.redacted))

    public = [_finding_dict(f, mask, pairs_by_path.get(f.path, [])) for f in findings]

    assets: dict[str, list] = defaultdict(list)
    for r in results:
        for tag in r.tags:
            assets[tag].append({"path": r.path, "size": r.size})

    databases = [{"path": r.path, **(r.db_info or {})} for r in results if r.db_info]
    notes = [{"path": r.path, "note": r.note} for r in results if r.note]

    return {
        "meta": {
            "tool": "exhume",
            "version": __version__,
            "generated": datetime.now(timezone.utc).isoformat(),
            "target": stats.root,
            "files_seen": stats.seen,
            "files_scanned": stats.scanned,
            "nested": stats.nested,
            "git_blobs": stats.git_blobs,
            "seconds": round(stats.elapsed, 2),
            "masked": mask,
            "ai_summary": stats.ai_summary,
            "ai_model": stats.ai_model,
        },
        "summary": {
            "total_findings": len(public),
            "verified_live": stats.verified_live,
            "suppressed_by_baseline": stats.suppressed,
            "by_severity": {
                sev.label: sum(1 for f in findings if f.severity == sev)
                for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
            },
            "by_type": dict(Counter(f.detector for f in findings)),
            "assets": {k: len(v) for k, v in assets.items()},
        },
        "findings": public,
        "assets": dict(assets),
        "databases": databases,
        "notes": notes,
    }


def write_json(payload: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, default=list)
