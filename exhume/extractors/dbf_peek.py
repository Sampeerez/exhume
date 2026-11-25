"""Read-only reader for dBase / xBase ``.dbf`` files (FoxPro, Clipper, legacy POS/ERP exports...).

The format is a simple, well-documented fixed-width table: a 32-byte header, one 32-byte field
descriptor per column, then fixed-width records. No external dependency needed — unlike the other
database engines Exhume reads, this one is simple enough to parse directly and reliably.

Memo fields (type ``M``, stored in a companion ``.dbt``/``.fpt`` file) are not followed: without it
we would only find an internal pointer, not the text, so those cells are skipped rather than
reported as garbage.
"""
from __future__ import annotations

import os
import struct

from .db_scan import DBScan
from .sqlite_peek import SENSITIVE_COL

_MAX_CELL_LEN = 1500
_ENCODINGS = ("utf-8", "cp1252", "latin-1")


def _decode(raw: bytes) -> str:
    for enc in _ENCODINGS:
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", "replace")


def _read_fields(f) -> list[tuple[str, str, int]]:
    """Return [(name, type, length), ...] by reading field descriptors until the 0x0D terminator."""
    fields = []
    while True:
        desc = f.read(32)
        if not desc or desc[0:1] == b"\x0d":
            break
        if len(desc) < 32:
            break
        name = desc[:11].split(b"\x00")[0].decode("ascii", "replace")
        ftype = chr(desc[11])
        length = desc[16]
        fields.append((name, ftype, length))
    return fields


def peek(path: str, max_tables: int = 1) -> dict:
    """DBF files hold exactly one table (the file itself); 'tables' has a single entry."""
    info: dict = {"tables": [], "sensitive_columns": []}
    try:
        with open(path, "rb") as f:
            header = f.read(32)
            if len(header) < 32:
                info["error"] = "TooShort"
                return info
            n_records = struct.unpack("<I", header[4:8])[0]
            f.seek(32)
            fields = _read_fields(f)
    except OSError as exc:
        info["error"] = type(exc).__name__
        return info
    cols = [name for name, _, _ in fields]
    name = os.path.splitext(os.path.basename(path))[0]
    info["tables"].append({"name": name, "rows": n_records, "columns": cols})
    for col in cols:
        if SENSITIVE_COL.search(col):
            info["sensitive_columns"].append(f"{name}.{col}")
    return info


def scan_contents(path: str, max_rows: int = 5000, max_cell: int = _MAX_CELL_LEN,
                  max_lines: int = 150_000) -> DBScan:
    """Read every (non-memo) field of every record as a ``"column=value"`` line."""
    scan = DBScan()
    try:
        with open(path, "rb") as f:
            header = f.read(32)
            if len(header) < 32 or header[0] not in (0x02, 0x03, 0x04, 0x05, 0x30, 0x31, 0x32,
                                                      0x43, 0x63, 0x7B, 0x83, 0x8B, 0x8E, 0xF5):
                return scan  # not a recognizable dBase version byte -> not ours
            n_records = struct.unpack("<I", header[4:8])[0]
            header_len = struct.unpack("<H", header[8:10])[0]
            record_len = struct.unpack("<H", header[10:12])[0]
            f.seek(32)
            fields = _read_fields(f)
            if not fields or record_len <= 1:
                return scan
            scan.ok = True
            table = os.path.splitext(os.path.basename(path))[0]
            scan.tables_scanned = 1
            f.seek(header_len)
            limit = min(n_records, max_rows) if max_rows else n_records
            if n_records > limit:
                scan.truncated = True
            for ridx in range(1, limit + 1):
                if len(scan.lines) >= max_lines:
                    scan.truncated = True
                    break
                raw = f.read(record_len)
                if len(raw) < record_len:
                    break
                scan.rows_scanned += 1
                if raw[0:1] == b"*":
                    continue  # soft-deleted record
                pos = 1
                for fname, ftype, flen in fields:
                    cell = raw[pos:pos + flen]
                    pos += flen
                    if ftype == "M":
                        continue  # memo pointer only, not the text
                    text = _decode(cell).strip().strip("\x00")
                    if not text or ftype == "L" and text in ("?",):
                        continue
                    scan.lines.append(f"{fname}={text[:max_cell]}")
                    scan.locations.append((table, fname, ridx))
    except (OSError, struct.error):
        return DBScan()
    return scan
