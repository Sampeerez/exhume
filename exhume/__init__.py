"""Exhume — sensitive-data discovery and verification suite for security audits.

Modular package. Main entry points:
    from exhume import Scanner, Config
    from exhume.cli import main
"""
from __future__ import annotations

__version__ = "7.1.0"
__author__ = "Exhume contributors"
__license__ = "MIT"

from .config import Config  # noqa: E402
from .models import FileResult, Finding, ScanStats, Severity  # noqa: E402
from .scanner import Scanner  # noqa: E402

__all__ = [
    "Config",
    "Scanner",
    "Finding",
    "FileResult",
    "ScanStats",
    "Severity",
    "__version__",
]
