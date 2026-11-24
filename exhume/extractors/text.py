"""Binary-aware text reading and string extraction."""
from __future__ import annotations

import re

_ASCII_RUN = re.compile(rb"[\x20-\x7e]{6,}")
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
_NUL_RATIO = 0.02  # > 2% null bytes => treated as binary


def extract_strings(raw: bytes, cap: int = 2_000_000) -> str:
    """Extract printable ASCII and UTF-16LE runs from binary data."""
    parts = [m.group().decode("ascii", "replace") for m in _ASCII_RUN.finditer(raw)]
    parts += [m.group().decode("utf-16le", "replace") for m in _UTF16_RUN.finditer(raw)]
    return "\n".join(parts)[:cap]


def read_textish(path: str, max_bytes: int, strings_mode: bool) -> tuple[str | None, str]:
    """Read a file as text. If it looks binary: strings (if enabled) or skip.

    Returns (text|None, method).
    """
    try:
        with open(path, "rb") as f:
            raw = f.read(max_bytes)
    except OSError as exc:
        return None, f"error:{type(exc).__name__}"
    if raw and raw.count(0) / len(raw) > _NUL_RATIO:
        if strings_mode:
            return extract_strings(raw), "strings"
        return None, "binary"
    return raw.decode("utf-8", errors="replace"), "text"
