"""Content extractors: magic, text, documents, archives, OCR, SQLite."""
from __future__ import annotations

from . import magic
from .archives import ExtractionBudget, extract, safe_join
from .db_registry import engine_for as db_engine_for
from .db_scan import DBScan
from .documents import extract_document
from .ocr import ocr_image
from .sqlite_peek import peek as sqlite_peek
from .sqlite_peek import scan_contents as sqlite_scan_contents
from .text import extract_strings, read_textish

__all__ = [
    "magic",
    "extract",
    "ExtractionBudget",
    "safe_join",
    "extract_document",
    "ocr_image",
    "sqlite_peek",
    "sqlite_scan_contents",
    "db_engine_for",
    "DBScan",
    "read_textish",
    "extract_strings",
]
