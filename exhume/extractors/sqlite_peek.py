"""Read-only inspection AND content extraction of SQLite databases.

``peek`` lists tables/columns for the report. ``scan_contents`` goes further: it reads
every cell of every table so the detector engine can find credentials, IPs and PII
*inside* the data, not just suspicious column names. A BLOB cell whose bytes look like
a known file format (an embedded document, archive, key or another database) is handed
back to the caller so it can be scanned recursively, the same way a nested archive is.
"""
from __future__ import annotations

import re
import sqlite3

from .db_scan import DBScan
from .magic import RECURSE_MAGICS, sniff_magic_bytes

SENSITIVE_COL = re.compile(
    r"(?i)(pass|pwd|secret|token|hash|salt|credit|card|cvv|iban|ssn|dni|"
    r"email|phone|tele|api|key|auth|session|cookie)"
)

_MAX_CELL_LEN = 1500        # chars kept per cell value (longer ones are truncated, not dropped)
_SKIP_CELL_LEN = 20000      # cells longer than this (e.g. embedded HTML) are not value-scanned
_MIN_BLOB_LEN = 64          # smaller blobs aren't worth a recursive file extraction


def peek(path: str, max_tables: int = 200) -> dict:
    """List tables, row counts and suspicious columns without modifying the file."""
    info: dict = {"tables": [], "sensitive_columns": []}
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True, timeout=2)
    except Exception as exc:
        info["error"] = type(exc).__name__
        return info
    try:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()][:max_tables]
        for t in tables:
            try:
                cur.execute(f'SELECT COUNT(*) FROM "{t}"')
                rows = cur.fetchone()[0]
            except Exception:
                rows = None
            cols = []
            try:
                cur.execute(f'PRAGMA table_info("{t}")')
                cols = [c[1] for c in cur.fetchall()]
            except Exception:
                pass
            info["tables"].append({"name": t, "rows": rows, "columns": cols})
            for col in cols:
                if SENSITIVE_COL.search(col):
                    info["sensitive_columns"].append(f"{t}.{col}")
    except Exception as exc:
        info["error"] = type(exc).__name__
    finally:
        con.close()
    return info


def scan_contents(path: str, max_tables: int = 100, max_rows: int = 5000,
                  max_cell: int = _MAX_CELL_LEN, max_lines: int = 150_000) -> DBScan:
    """Read every table/row/column so secrets hidden *in the data* are not missed.

    Each non-null cell becomes one ``"column=value"`` line, so the existing credential/
    PII/IP detectors (which look for ``key=value`` patterns) apply unchanged. Large
    tables are sampled (first *max_rows* rows) rather than skipped outright, and the
    result says so via ``truncated`` instead of silently losing data.
    """
    scan = DBScan()
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True, timeout=2)
    except Exception:
        return scan
    scan.ok = True
    try:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        if len(tables) > max_tables:
            scan.truncated = True
            tables = tables[:max_tables]
        for t in tables:
            if len(scan.lines) >= max_lines:
                scan.truncated = True
                break
            try:
                rcur = con.cursor()
                rcur.execute(f'SELECT * FROM "{t}" LIMIT ?', (max_rows + 1,))
                cols = [d[0] for d in rcur.description]
            except Exception:
                continue
            scan.tables_scanned += 1
            for ridx, row in enumerate(rcur, start=1):
                if ridx > max_rows:
                    scan.truncated = True
                    break
                if len(scan.lines) >= max_lines:
                    scan.truncated = True
                    break
                scan.rows_scanned += 1
                for col, val in zip(cols, row):
                    if val is None:
                        continue
                    if isinstance(val, (bytes, bytearray)):
                        raw = bytes(val)
                        kind = sniff_magic_bytes(raw[:16])
                        if kind in RECURSE_MAGICS and len(raw) >= _MIN_BLOB_LEN:
                            scan.blobs.append((t, col, ridx, raw))
                            continue
                        try:
                            sval = raw.decode("utf-8")
                        except UnicodeDecodeError:
                            continue  # opaque binary blob: nothing more we can do with it
                    else:
                        sval = str(val)
                    if not sval or len(sval) > _SKIP_CELL_LEN:
                        continue
                    scan.lines.append(f"{col}={sval[:max_cell]}")
                    scan.locations.append((t, col, ridx))
    except Exception:
        pass
    finally:
        con.close()
    return scan
