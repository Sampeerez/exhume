"""Picks the right content reader for a database file, across every engine Exhume understands.

SQLite is detected by its content (magic bytes), so a renamed file is still caught; the rest are
matched by extension. Each entry is ``(peek_fn, scan_fn, label)`` with the shared shapes documented
in :mod:`db_scan`. ``engine_for`` returns ``None`` when the file is a database Exhume recognizes but
cannot structurally parse (either no reader exists for that engine, or an optional one like
``mdbtools`` isn't installed) — the caller then falls back to string-scanning the raw bytes.
"""
from __future__ import annotations

from . import bson_peek, dbf_peek, mdb_peek, sqlite_peek

_BY_EXT = {
    ".dbf": (dbf_peek.peek, dbf_peek.scan_contents, "dbf-content"),
    ".bson": (bson_peek.peek, bson_peek.scan_contents, "bson-content"),
}
_MDB_EXT = {".mdb", ".accdb"}
_SQLITE_EXT = {".db", ".sqlite", ".sqlite3", ".db3", ".sqlitedb"}


def engine_for(ext: str, magic_kind: str | None):
    """Return (peek_fn, scan_fn, label) for *ext*/*magic_kind*, or None if unavailable."""
    if magic_kind == "database" or ext in _SQLITE_EXT:
        return sqlite_peek.peek, sqlite_peek.scan_contents, "sqlite-content"
    if ext in _MDB_EXT:
        return (mdb_peek.peek, mdb_peek.scan_contents, "access-content") if mdb_peek.available() else None
    return _BY_EXT.get(ext)
