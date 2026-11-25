"""Shared result shape for every database content reader (SQLite, DBF, MongoDB dumps, Access...).

Each engine-specific module (``sqlite_peek``, ``dbf_peek``, ``bson_peek``, ``mdb_peek``) turns a
database file into the SAME two things, so the scanner and the report don't need to know which
engine produced them:

- ``peek(path)`` — a metadata dict ``{"tables": [{"name","rows","columns"}], "sensitive_columns": []}``
  for the report ("Databases" section).
- ``scan_contents(path, max_rows)`` — a :class:`DBScan`: every cell as a ``"column=value"`` line (so
  the existing credential/PII/IP detectors apply unchanged), with its (table, column, row) location.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DBScan:
    """Result of reading a database's actual row data."""
    lines: list[str] = field(default_factory=list)                        # "column=value", one per cell
    locations: list[tuple[str, str, int]] = field(default_factory=list)   # (table, column, row) per line
    blobs: list[tuple[str, str, int, bytes]] = field(default_factory=list)  # embedded-file candidates
    truncated: bool = False
    tables_scanned: int = 0
    rows_scanned: int = 0
    ok: bool = False          # False means the file could not even be opened/parsed
