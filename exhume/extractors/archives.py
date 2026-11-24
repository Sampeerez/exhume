"""Safe, recursive extraction of compressed archives.

Protects against zip bombs (byte/file budget) and path traversal (destinations
are validated to stay inside the temporary directory).
"""
from __future__ import annotations

import bz2
import gzip
import lzma
import os
import shutil
import tarfile
import zipfile

from .magic import ARCH_7Z, ARCH_RAR, ARCH_SINGLE, ARCH_TAR, ARCH_ZIP

_CHUNK = 262144


class ExtractionBudget:
    """Shared limit for an entire chain of nested archives."""

    def __init__(self, max_bytes: int, max_files: int):
        self.bytes = max_bytes
        self.files = max_files
        self.exhausted = False

    def consume(self, n: int) -> bool:
        self.files -= 1
        self.bytes -= n
        if self.files < 0 or self.bytes < 0:
            self.exhausted = True
        return not self.exhausted


def safe_join(base: str, name: str) -> str | None:
    """Join base+name, preventing path traversal. Returns None if it escapes."""
    dest = os.path.realpath(os.path.join(base, name))
    real_base = os.path.realpath(base)
    if dest != real_base and not dest.startswith(real_base + os.sep):
        return None
    return dest


def _extract_zip(path, tmp, budget) -> bool:
    with zipfile.ZipFile(path) as z:
        for member in z.infolist():
            if member.is_dir():
                continue
            if not budget.consume(member.file_size):
                break
            dest = safe_join(tmp, member.filename)
            if not dest:
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            try:
                with z.open(member) as src, open(dest, "wb") as out:
                    shutil.copyfileobj(src, out, _CHUNK)
            except Exception:
                pass
    return True


def _extract_tar(path, tmp, budget) -> bool:
    with tarfile.open(path, "r:*") as t:
        for member in t.getmembers():
            if not member.isfile():
                continue
            if not budget.consume(member.size):
                break
            dest = safe_join(tmp, member.name)
            if not dest:
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            try:
                src = t.extractfile(member)
                if src:
                    with open(dest, "wb") as out:
                        shutil.copyfileobj(src, out, _CHUNK)
            except Exception:
                pass
    return True


def _extract_single(path, ext, tmp, budget) -> bool:
    opener = {".gz": gzip.open, ".bz2": bz2.open, ".xz": lzma.open}[ext]
    inner = os.path.basename(path)[: -len(ext)] or "content"
    dest = os.path.join(tmp, inner)
    with opener(path, "rb") as src, open(dest, "wb") as out:
        shutil.copyfileobj(src, out, _CHUNK)
    budget.consume(os.path.getsize(dest))
    return True


def extract(path: str, ext: str, tmp: str, budget: ExtractionBudget) -> bool:
    """Extract *path* into *tmp*. Returns True if the format could be handled."""
    try:
        if ext in ARCH_ZIP or ext == ".zip":
            return _extract_zip(path, tmp, budget)
        if ext in ARCH_TAR or ext in (".tgz", ".tbz2", ".txz"):
            return _extract_tar(path, tmp, budget)
        if ext in ARCH_SINGLE:
            return _extract_single(path, ext, tmp, budget)
        if ext in ARCH_7Z:
            try:
                import py7zr  # type: ignore
                with py7zr.SevenZipFile(path, "r") as z:
                    z.extractall(tmp)
                return True
            except ImportError:
                return False
        if ext in ARCH_RAR:
            try:
                import rarfile  # type: ignore
                with rarfile.RarFile(path) as r:
                    r.extractall(tmp)
                return True
            except ImportError:
                return False
    except Exception:
        return False
    return False
