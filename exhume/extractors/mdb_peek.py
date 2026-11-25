"""Read-only reader for Microsoft Access databases (``.mdb``, ``.accdb``).

Access' Jet/ACE format is proprietary and not something to parse by hand, but the open-source
``mdbtools`` suite reads it fully, cross-platform, without MS Access or Windows — the same role
``tesseract`` plays for OCR: an optional system tool, auto-detected, with a graceful fallback
(opaque string-scanning) when it isn't installed.

Install: ``brew install mdbtools`` / ``apt install mdbtools``.
"""
from __future__ import annotations

import csv
import io
import shutil
import subprocess

from .db_scan import DBScan
from .sqlite_peek import SENSITIVE_COL

_TIMEOUT = 20
_MAX_CELL_LEN = 1500
_MAX_TABLES = 100


def available() -> bool:
    return shutil.which("mdb-tables") is not None and shutil.which("mdb-export") is not None


def _tables(path: str) -> list[str]:
    out = subprocess.run(["mdb-tables", "-1", path], capture_output=True, timeout=_TIMEOUT, text=True)
    if out.returncode != 0:
        return []
    return [t for t in out.stdout.splitlines() if t.strip()]


def _export(path: str, table: str, max_rows: int):
    """Return (header, rows, truncated) for *table* via `mdb-export`, capped at *max_rows* rows."""
    out = subprocess.run(["mdb-export", path, table], capture_output=True, timeout=_TIMEOUT, text=True,
                         errors="replace")
    if out.returncode != 0 or not out.stdout:
        return [], False
    reader = csv.reader(io.StringIO(out.stdout))
    try:
        header = next(reader)
    except StopIteration:
        return [], False
    rows = []
    truncated = False
    for i, row in enumerate(reader, start=1):
        if max_rows and i > max_rows:
            truncated = True
            break
        rows.append(row)
    return header, rows, truncated


def peek(path: str, max_tables: int = _MAX_TABLES) -> dict:
    info: dict = {"tables": [], "sensitive_columns": []}
    if not available():
        info["error"] = "mdbtools not installed"
        return info
    try:
        tables = _tables(path)[:max_tables]
    except Exception as exc:
        info["error"] = type(exc).__name__
        return info
    for t in tables:
        try:
            header, rows, _ = _export(path, t, max_rows=1)
        except Exception:
            header = []
        info["tables"].append({"name": t, "rows": None, "columns": header})
        for col in header:
            if SENSITIVE_COL.search(col):
                info["sensitive_columns"].append(f"{t}.{col}")
    return info


def scan_contents(path: str, max_rows: int = 5000, max_cell: int = _MAX_CELL_LEN,
                  max_lines: int = 150_000) -> DBScan:
    scan = DBScan()
    if not available():
        return scan
    try:
        tables = _tables(path)[:_MAX_TABLES]
    except Exception:
        return scan
    if not tables:
        return scan
    scan.ok = True
    for t in tables:
        if len(scan.lines) >= max_lines:
            scan.truncated = True
            break
        try:
            header, rows, truncated = _export(path, t, max_rows)
        except Exception:
            continue
        if truncated:
            scan.truncated = True
        scan.tables_scanned += 1
        for ridx, row in enumerate(rows, start=1):
            if len(scan.lines) >= max_lines:
                scan.truncated = True
                break
            scan.rows_scanned += 1
            for col, val in zip(header, row):
                if not val:
                    continue
                scan.lines.append(f"{col}={val[:max_cell]}")
                scan.locations.append((t, col, ridx))
    return scan
