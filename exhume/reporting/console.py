"""Readable, colored console report."""
from __future__ import annotations

from collections import defaultdict

from ..config import Config
from ..console import Colors as C
from ..models import FileResult, ScanStats, Severity, Verified, finding_sort_key
from .json_report import human_size

_SEV_COLOR = {3: C.R, 2: C.Y, 1: C.B}
_MIN_SEV = {"all": 1, "medium": 1, "high": 2, "critical": 3}


def _vtag(verified: Verified) -> str:
    if verified is Verified.LIVE:
        return f"{C.G}[✓ LIVE]{C.END} "
    if verified is Verified.DEAD:
        return f"{C.GR}[✗ dead]{C.END} "
    if verified is Verified.VALID:
        return f"{C.G}[✓ valid]{C.END} "
    return ""


def print_report(results: list[FileResult], stats: ScanStats, cfg: Config) -> None:
    print()
    print(f"{C.BOLD}{C.CY}╔═ Exhume — audit report ═╗{C.END}")
    print(f"{C.GR}Target:{C.END} {stats.root}")
    line = (f"{C.GR}Seen:{C.END} {stats.seen}  {C.GR}scanned:{C.END} {stats.scanned}  "
            f"{C.GR}nested:{C.END} {stats.nested}  {C.GR}git-history:{C.END} {stats.git_blobs}  "
            f"{C.GR}time:{C.END} {stats.elapsed:.1f}s")
    if stats.coverage:
        labels = {"scanned": "content scanned", "archives": "archives unpacked",
                  "media_skipped": "media skipped", "binary_skipped": "binary skipped",
                  "document_failed": "documents unreadable", "ocr_unavailable": "images without OCR",
                  "too_big": "too big",
                  "timeout": "timed out", "error": "errors"}
        parts = [f"{v} {labels.get(k, k)}" for k, v in stats.coverage.items() if v]
        line += f"\n{C.GR}Coverage:{C.END} " + " · ".join(parts)
    if stats.suppressed:
        line += f"  {C.GR}baseline-hidden:{C.END} {stats.suppressed}"
    print(line)
    if cfg.verify:
        print(f"{C.G}{C.BOLD}Live credentials verified: {stats.verified_live}{C.END}")
    if stats.ai_summary:
        print(f"\n{C.M}{C.BOLD}── AI triage ({stats.ai_model}) ──{C.END}")
        print(stats.ai_summary.strip())
    print()

    findings = sorted((f for r in results for f in r.findings), key=finding_sort_key)
    if cfg.only_verified:
        findings = [f for f in findings if f.verified is Verified.LIVE]

    invalid = [f for f in findings if f.hidden]
    findings = [f for f in findings if not f.hidden]
    by_sev: dict[int, list] = defaultdict(list)
    for f in findings:
        by_sev[int(f.severity)].append(f)

    min_sev = _MIN_SEV[cfg.min_sev]
    if findings:
        print(f"{C.BOLD}── Secrets & sensitive data ──{C.END}")
        for sev in (3, 2, 1):
            if sev < min_sev:
                continue
            group = by_sev.get(sev, [])
            if not group:
                continue
            col = _SEV_COLOR[sev]
            print(f"\n{col}{C.BOLD}[{Severity(sev).label}]{C.END} {col}{len(group)} finding(s){C.END}")
            per_type: dict[str, list] = defaultdict(list)
            for f in group:
                per_type[f.detector].append(f)
            for detector, items in sorted(per_type.items(), key=lambda x: -len(x[1])):
                print(f"  {col}▸ {detector}{C.END} ({len(items)})")
                for f in items[:cfg.show_per_type]:
                    detail = f"  {C.DIM}{f.detail}{C.END}" if f.detail else ""
                    value = f.redacted if cfg.mask else (f.secret or f.redacted)
                    print(f"    {_vtag(f.verified)}{C.DIM}{f.path}:{f.line}{C.END}  {C.W}{value}{C.END}{detail}")
                if len(items) > cfg.show_per_type:
                    print(f"    {C.GR}... and {len(items) - cfg.show_per_type} more{C.END}")
    else:
        extra = " verified" if cfg.only_verified else ""
        print(f"{C.G}No{extra} findings.{C.END}")

    if invalid:
        print(f"\n{C.GR}{len(invalid)} match(es) failed validation or were judged false positives "
              f"(checksum / host check / local AI) and are hidden here; they remain in the HTML (toggle) "
              f"and CSV/JSON exports.{C.END}")

    if cfg.only_verified:
        print()
        return

    _print_databases(results)
    _print_assets(results)
    print()


def _print_databases(results: list[FileResult]) -> None:
    dbs = [r for r in results if "database" in r.tags and r.ai_verdict != "false"]
    if not dbs:
        return
    print(f"\n{C.M}{C.BOLD}── Databases ({len(dbs)}) ──{C.END}")
    for r in dbs[:30]:
        print(f"  {C.M}▸{C.END} {r.path} {C.GR}({human_size(r.size)}){C.END}")
        di = r.db_info or {}
        if di.get("tables"):
            names = ", ".join(f"{t['name']}({t['rows']})" for t in di["tables"][:8])
            print(f"      {C.GR}tables:{C.END} {names}")
            if di.get("sensitive_columns"):
                print(f"      {C.Y}sensitive columns:{C.END} {', '.join(di['sensitive_columns'][:12])}")


def _print_assets(results: list[FileResult]) -> None:
    sections = [
        ("key_material", "Key material / certificates", C.R),
        ("sensitive_name", "Sensitive filenames", C.Y),
        ("executable", "Executables / binaries", C.CY),
        ("archive", "Archives", C.GR),
    ]
    for tag, title, color in sections:
        hits = [r for r in results if tag in r.tags and r.ai_verdict != "false"]
        if not hits:
            continue
        print(f"\n{color}{C.BOLD}── {title} ({len(hits)}) ──{C.END}")
        for r in hits[:25]:
            print(f"  {color}▸{C.END} {r.path} {C.GR}({human_size(r.size)}){C.END}")
        if len(hits) > 25:
            print(f"  {C.GR}... and {len(hits) - 25} more{C.END}")
