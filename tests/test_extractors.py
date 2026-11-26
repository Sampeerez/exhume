"""Tests for extractors: text, magic, sqlite, ocr."""
from __future__ import annotations

import sqlite3

from exhume.extractors import magic, ocr_image, read_textish, sqlite_peek
from exhume.extractors.text import extract_strings


def test_read_textish_text(tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("hello world")
    text, method = read_textish(str(p), 1_000_000, strings_mode=False)
    assert text == "hello world"
    assert method == "text"


def test_read_textish_binary_skipped(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"\x00\x01\x02\x00\x00\x00binary\x00\x00")
    text, method = read_textish(str(p), 1_000_000, strings_mode=False)
    assert text is None
    assert method == "binary"


def test_read_textish_strings_mode(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"\x00\x00AKIAIOSFODNN7EXAMPLE\x00\x00rubbish\x00")
    text, method = read_textish(str(p), 1_000_000, strings_mode=True)
    assert method == "strings"
    assert "AKIAIOSFODNN7EXAMPLE" in text


def test_read_textish_none_means_no_cap(tmp_path):
    """--max-size 0 (--deep) passes max_bytes=None for "no limit". A naive fix once passed a
    huge sentinel int to file.read() instead, which raised MemoryError trying to size a buffer
    up front — even for a perfectly ordinary, small file. None must mean "read to EOF", not
    "read up to some enormous number"."""
    p = tmp_path / "a.txt"
    p.write_text("hello world, no size cap")
    text, method = read_textish(str(p), None, strings_mode=False)
    assert text == "hello world, no size cap"
    assert method == "text"


def test_extract_strings_utf16():
    raw = b"h\x00e\x00l\x00l\x00o\x00w\x00o\x00r\x00l\x00d\x00"
    assert "helloworld" in extract_strings(raw)


def test_ext_of_compound():
    assert magic.ext_of("x.tar.gz") == ".tar.gz"
    assert magic.ext_of("x.TXT") == ".txt"


def test_classify_by_ext():
    assert "database" in magic.classify("x.sqlite", ".sqlite", None)
    assert "executable" in magic.classify("x.exe", ".exe", None)
    assert "sensitive_name" in magic.classify("id_rsa", "", None)


def test_classify_by_magic():
    assert "executable" in magic.classify("mystery", "", "executable")
    assert "key_material" in magic.classify("mystery", "", "key_material")


def test_sniff_magic_sqlite(tmp_path):
    db = tmp_path / "x.db"
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE t(a)")
    con.commit()
    con.close()
    assert magic.sniff_magic(str(db)) == "database"


def test_sqlite_peek(tmp_path):
    db = tmp_path / "x.db"
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE users(username TEXT, password TEXT)")
    con.execute("INSERT INTO users VALUES('a','b')")
    con.commit()
    con.close()
    info = sqlite_peek(str(db))
    assert any(t["name"] == "users" for t in info["tables"])
    assert any("password" in c for c in info["sensitive_columns"])


def test_ocr_missing_is_graceful(tmp_path):
    p = tmp_path / "x.png"
    p.write_bytes(b"\x89PNG\r\n")
    text, method = ocr_image(str(p))
    assert method in ("no-ocr", "ocr") or method.startswith("ocr-error")


def test_tesseract_available_reflects_ocr_ready():
    """A scan reported images silently skipped with no explanation — the generic "optional
    extras" check only verifies the pytesseract PYTHON package imports, which pip installs
    automatically; it says nothing about whether the system `tesseract` binary itself is
    actually callable, which pip can't install. tesseract_available() is the real check."""
    from exhume.extractors import ocr as ocr_mod
    assert ocr_mod.tesseract_available() == ocr_mod._ocr_ready()
