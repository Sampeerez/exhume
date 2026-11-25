"""Optional dependency management with fault-tolerant auto-installation.

The core runs on the standard library alone. Each extra widens coverage:
documents, exotic archives, SMB, S3, OCR and YAML rules.
"""
from __future__ import annotations

import importlib
import subprocess
import sys

from .console import Colors, eprint

# (pip_name, import_module, what_for)
OPTIONAL_DEPS = [
    ("pdfplumber", "pdfplumber", "PDF text"),
    ("python-docx", "docx", "Word .docx text"),
    ("openpyxl", "openpyxl", "Excel .xlsx cells"),
    ("python-pptx", "pptx", "PowerPoint .pptx text"),
    ("extract-msg", "extract_msg", "Outlook .msg emails"),
    ("impacket", "impacket.smbconnection", "unmounted SMB"),
    ("py7zr", "py7zr", ".7z archives"),
    ("rarfile", "rarfile", ".rar archives"),
    ("PyYAML", "yaml", "YAML rules"),
    ("boto3", "boto3", "S3 buckets"),
    ("pymongo", "bson", "MongoDB dump (.bson) content"),
]
OCR_DEPS = [
    ("pillow", "PIL", "images for OCR"),
    ("pytesseract", "pytesseract", "OCR engine"),
]


def _module_available(module: str) -> bool:
    try:
        importlib.import_module(module)
        return True
    except Exception:
        return False


_pip_ready: bool | None = None


def _pip_available() -> bool:
    try:
        return subprocess.run([sys.executable, "-m", "pip", "--version"],
                              capture_output=True, timeout=15).returncode == 0
    except Exception:
        return False


def ensure_pip() -> bool:
    """Make sure ``python -m pip`` actually works before trying to use it.

    Tools like pipx and uv deliberately strip pip out of the virtual environment they
    install a package into (to stop people mutating it directly) — so on a globally
    installed Exhume, ``python -m pip install ...`` fails with "No module named pip"
    before it ever gets to download anything, which looks identical to "no internet" or
    "no compiler". ``ensurepip`` (part of the standard library) re-bootstraps a real pip
    into the current interpreter in that case; this is cached so it only runs once.
    """
    global _pip_ready
    if _pip_ready is None:
        _pip_ready = _pip_available()
    if not _pip_ready:
        try:
            subprocess.run([sys.executable, "-m", "ensurepip", "--upgrade"],
                          capture_output=True, timeout=120)
        except Exception:
            pass
        _pip_ready = _pip_available()
    return _pip_ready


def pip_install(pkg: str, timeout: int = 180) -> bool:
    """Install a package with pip, trying variants for managed environments."""
    if not ensure_pip():
        return False
    base = [sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", pkg]
    for extra in ([], ["--break-system-packages"], ["--user", "--break-system-packages"]):
        try:
            if subprocess.run(base + extra, capture_output=True, timeout=timeout).returncode == 0:
                return True
        except Exception:
            continue
    return False


def ensure(deps, autoinstall: bool, quiet: bool = True) -> dict[str, bool]:
    """Ensure availability; returns {short_module: available}."""
    have: dict[str, bool] = {}
    for pkg, module, _why in deps:
        short = module.split(".")[0]
        ok = _module_available(module)
        if not ok and autoinstall:
            if not quiet:
                eprint(f"{Colors.GR}  installing {pkg}...{Colors.END}")
            if pip_install(pkg):
                importlib.invalidate_caches()
                ok = _module_available(module)
        have[short] = ok
    return have


def resolve(config_autoinstall: bool, want_ocr: bool, quiet: bool = True) -> dict[str, bool]:
    """Resolve all optional dependencies according to configuration."""
    have = ensure(OPTIONAL_DEPS, config_autoinstall, quiet)
    if want_ocr:
        have.update(ensure(OCR_DEPS, config_autoinstall, quiet))
    else:
        have.setdefault("PIL", _module_available("PIL"))
        have.setdefault("pytesseract", _module_available("pytesseract"))
    return have
