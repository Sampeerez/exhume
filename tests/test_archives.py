"""Tests for archive extraction (including nested and protection)."""
from __future__ import annotations

import tarfile
import zipfile

from exhume.extractors.archives import ExtractionBudget, extract, safe_join
from exhume.scanner import process_entry


def test_safe_join_blocks_traversal(tmp_path):
    base = str(tmp_path)
    assert safe_join(base, "ok/file.txt") is not None
    assert safe_join(base, "../../etc/passwd") is None


def test_nested_zip_in_tar(tmp_path, cfg):
    # zip (con secreto) dentro de tar.gz
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("deep/.env", "API_KEY=ghp_" + "1234567890abcdefABCDEF1234567890abcd\n")
    outer = tmp_path / "eviden.tar.gz"
    with tarfile.open(outer, "w:gz") as t:
        t.add(inner, arcname="inner.zip")
    inner.unlink()

    results = process_entry(str(outer), str(outer), cfg)
    detectors = {f.detector for r in results for f in r.findings}
    assert "GitHub token" in detectors
    # La ruta debe reflejar el anidamiento
    paths = [f.path for r in results for f in r.findings]
    assert any("::>" in p for p in paths)


def test_budget_limits_extraction(tmp_path):
    big = tmp_path / "b.zip"
    with zipfile.ZipFile(big, "w") as z:
        for i in range(10):
            z.writestr(f"f{i}.txt", "x" * 1000)
    budget = ExtractionBudget(max_bytes=10_000_000, max_files=3)
    dest = tmp_path / "out"
    dest.mkdir()
    extract(str(big), ".zip", str(dest), budget)
    assert budget.exhausted  # ran out of the file quota


def test_zip_scanned_as_archive(tmp_path, cfg):
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("creds.txt", "AKIAIOSFODNN7EXAMPLE")
    results = process_entry(str(z), str(z), cfg)
    assert any(f.detector == "AWS Access Key ID" for r in results for f in r.findings)
