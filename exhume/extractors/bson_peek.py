"""Read-only reader for MongoDB dump files (``mongodump`` output, ``.bson``).

BSON is a simple, fully-documented binary format (unlike a live database engine's on-disk pages),
so every document can be decoded and every field value scanned, nested documents included — the
same "every row/column" coverage SQLite gets.

Uses the ``bson`` module that ships inside the official, actively-maintained ``pymongo`` package
(no MongoDB server needed; it only decodes bytes). Exhume auto-installs it like any other extra.
"""
from __future__ import annotations

import os

from .db_scan import DBScan
from .sqlite_peek import SENSITIVE_COL

_MAX_CELL_LEN = 1500
_MAX_DOCS_PEEK = 20_000


def _flatten(prefix: str, value, out: list[tuple[str, str]], blobs: list[bytes], depth: int = 0) -> None:
    """Turn a (possibly nested) document into ("field.path", "value") pairs."""
    if depth > 6:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            _flatten(f"{prefix}.{k}" if prefix else str(k), v, out, blobs, depth + 1)
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value[:50]):
            _flatten(f"{prefix}[{i}]", v, out, blobs, depth + 1)
    elif isinstance(value, (bytes, bytearray)):
        if len(value) >= 64:
            blobs.append((prefix, bytes(value)))
    elif value is not None and value != "":
        out.append((prefix, str(value)))


def _available():
    try:
        from bson import decode_file_iter  # type: ignore
        return decode_file_iter
    except Exception:
        return None


def peek(path: str, max_tables: int = 1) -> dict:
    name = os.path.splitext(os.path.basename(path))[0]
    info: dict = {"tables": [], "sensitive_columns": []}
    decode_file_iter = _available()
    if not decode_file_iter:
        info["error"] = "ImportError"
        return info
    cols: set[str] = set()
    n = 0
    try:
        with open(path, "rb") as f:
            for doc in decode_file_iter(f):
                n += 1
                cols.update(doc.keys())
                if n >= _MAX_DOCS_PEEK:
                    break
    except Exception as exc:
        info["error"] = type(exc).__name__
        return info
    if n == 0:
        info["error"] = "Empty"
        return info
    cols = sorted(cols)
    info["tables"].append({"name": name, "rows": n, "columns": cols})
    for col in cols:
        if SENSITIVE_COL.search(col):
            info["sensitive_columns"].append(f"{name}.{col}")
    return info


def scan_contents(path: str, max_rows: int = 5000, max_cell: int = _MAX_CELL_LEN,
                  max_lines: int = 150_000) -> DBScan:
    scan = DBScan()
    decode_file_iter = _available()
    if not decode_file_iter:
        return scan
    table = os.path.splitext(os.path.basename(path))[0]
    try:
        with open(path, "rb") as f:
            for ridx, doc in enumerate(decode_file_iter(f), start=1):
                if ridx > max_rows:
                    scan.truncated = True
                    break
                if len(scan.lines) >= max_lines:
                    scan.truncated = True
                    break
                scan.ok = True
                scan.rows_scanned += 1
                pairs: list[tuple[str, str]] = []
                blobs: list[bytes] = []
                _flatten("", doc, pairs, blobs)
                for field, value in pairs:
                    scan.lines.append(f"{field}={value[:max_cell]}")
                    scan.locations.append((table, field, ridx))
                for field, raw in blobs:
                    scan.blobs.append((table, field, ridx, raw))
    except Exception:
        return scan if scan.ok else DBScan()
    scan.tables_scanned = 1 if scan.ok else 0
    return scan
