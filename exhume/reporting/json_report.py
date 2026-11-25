"""Shared report payload builder and JSON output.

By default findings show the REAL secret values (the report is for the pentester).
Pass mask=True (CLI --mask) to produce a client-safe report with values redacted.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone

from .. import __version__
from ..models import (
    FileResult,
    FindingGroup,
    ScanStats,
    Severity,
    Verified,
    finding_sort_key,
    group_findings,
    group_sort_key,
)


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


_MAX_LOCATIONS = 500  # locations listed per group in the report (the count itself is never capped)


def _finding_dict(g: FindingGroup, mask: bool, line_pairs: list[tuple[str, str]]) -> dict:
    f = g.rep
    if mask:
        value = f.redacted
        context = _mask_text(f.context, line_pairs)
        block = [[n, _mask_text(t, line_pairs)] for n, t in f.context_block]
    else:
        value = f.secret if f.secret is not None else f.redacted
        context = f.context
        block = [[n, t] for n, t in f.context_block]
    locs = g.locations[:_MAX_LOCATIONS]
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
        "verifier": f.verifier,
        "ai": f.ai_verdict,
        "ai_note": f.ai_note,
        "detail": f.detail,
        "fingerprint": g.fingerprint,
        "occurrences": g.count,
        "locations": [{"path": p, "line": ln, "col": c} for p, ln, c in locs],
        "locations_truncated": max(0, g.count - len(locs)),
    }


def build_payload(results: list[FileResult], stats: ScanStats, mask: bool = False) -> dict:
    findings = sorted((f for r in results for f in r.findings), key=finding_sort_key)
    # The same value (a password, an email, a key...) is reported ONCE, with every location
    # it was found in, instead of once per occurrence.
    groups = sorted(group_findings(findings), key=group_sort_key)

    # Pairs per (path, line-vicinity) for masking the surrounding context blocks.
    pairs_by_path: dict[str, list[tuple[str, str]]] = defaultdict(list)
    if mask:
        for g in groups:
            if g.rep.secret:
                pairs_by_path[g.rep.path].append((g.rep.secret, g.rep.redacted))

    public = [_finding_dict(g, mask, pairs_by_path.get(g.rep.path, [])) for g in groups]

    assets: dict[str, list] = defaultdict(list)
    for r in results:
        for tag in r.tags:
            assets[tag].append({"path": r.path, "size": r.size, "ai": r.ai_verdict})

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
            "coverage": stats.coverage,
            "ai_engine": stats.ai_engine,
            "ai_filter": stats.ai_filter,
            "nested": stats.nested,
            "git_blobs": stats.git_blobs,
            "seconds": round(stats.elapsed, 2),
            "masked": mask,
            "ai_summary": stats.ai_summary,
            "ai_model": stats.ai_model,
        },
        "summary": {
            "total_findings": len(groups),
            "total_occurrences": len(findings),
            "verified_live": sum(1 for g in groups if g.rep.verified is Verified.LIVE),
            "invalid": sum(1 for g in groups if g.rep.verified.value == "invalid"),
            "ai_false": sum(1 for g in groups if g.rep.ai_verdict == "false"),
            "hidden": sum(1 for g in groups if g.rep.hidden),
            "suppressed_by_baseline": stats.suppressed,
            "by_severity": {
                sev.label: sum(1 for g in groups if g.rep.severity == sev and not g.rep.hidden)
                for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
            },
            "by_type": dict(Counter(g.rep.detector for g in groups)),
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
