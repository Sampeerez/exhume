"""Tests for the extra database content readers: DBF, MongoDB dump (.bson), Access (mdbtools)."""
from __future__ import annotations

import struct

import pytest

from exhume.extractors import bson_peek, db_registry, dbf_peek, mdb_peek

# ---------------------------------------------------------------- DBF (dBase)

def _write_dbf(path, fields, rows):
    """Minimal dBase III writer, just enough to produce a valid fixture for the reader."""
    record_len = 1 + sum(length for _, _, length in fields)
    header_len = 32 + len(fields) * 32 + 1
    with open(path, "wb") as f:
        f.write(struct.pack("<BBBBIHH20x", 0x03, 24, 1, 1, len(rows), header_len, record_len))
        for name, ftype, length in fields:
            f.write(name.encode("ascii")[:10].ljust(11, b"\x00") + ftype.encode() +
                    b"\x00" * 4 + bytes([length]) + b"\x00" * 15)
        f.write(b"\x0d")
        for row in rows:
            rec = b" "
            for (_, _, length), val in zip(fields, row):
                rec += str(val).encode("ascii")[:length].ljust(length, b" ")
            f.write(rec)
        f.write(b"\x1a")


def test_dbf_reads_every_row_and_column(tmp_path):
    p = tmp_path / "clientes.dbf"
    fields = [("ID", "N", 6), ("EMAIL", "C", 40), ("PASSWORD", "C", 30)]
    rows = [(1, "alice@corp.com", "hunter2hunter2!!"), (2, "bob@corp.com", "Sup3rS3cret!2024")]
    _write_dbf(p, fields, rows)

    meta = dbf_peek.peek(str(p))
    assert meta["tables"][0]["columns"] == ["ID", "EMAIL", "PASSWORD"]
    assert meta["tables"][0]["rows"] == 2
    assert "clientes.EMAIL" in meta["sensitive_columns"]

    scan = dbf_peek.scan_contents(str(p))
    assert scan.ok and scan.rows_scanned == 2
    assert "PASSWORD=hunter2hunter2!!" in scan.lines
    assert ("clientes", "EMAIL", 1) in scan.locations


def test_dbf_rejects_non_dbf_files(tmp_path):
    p = tmp_path / "notadbf.dbf"
    p.write_bytes(b"not a dbf file at all")
    scan = dbf_peek.scan_contents(str(p))
    assert not scan.ok


def test_dbf_respects_max_rows(tmp_path):
    p = tmp_path / "big.dbf"
    fields = [("N", "C", 10)]
    rows = [(f"val{i}",) for i in range(20)]
    _write_dbf(p, fields, rows)
    scan = dbf_peek.scan_contents(str(p), max_rows=5)
    assert scan.truncated
    assert scan.rows_scanned == 5


# ---------------------------------------------------------------- MongoDB (.bson)

def _write_bson(path, docs):
    bson = pytest.importorskip("bson")
    with open(path, "wb") as f:
        for d in docs:
            f.write(bson.encode(d))


def test_bson_reads_nested_documents(tmp_path):
    p = tmp_path / "users.bson"
    _write_bson(p, [
        {"_id": 1, "email": "alice@corp.com", "profile": {"aws_key": "AKIAIOSFODNN7EXAMPLE"}},
        {"_id": 2, "email": "bob@corp.com"},
    ])
    meta = bson_peek.peek(str(p))
    assert meta["tables"][0]["rows"] == 2
    assert "users.email" in meta["sensitive_columns"]

    scan = bson_peek.scan_contents(str(p))
    assert scan.ok
    assert "email=alice@corp.com" in scan.lines
    assert "profile.aws_key=AKIAIOSFODNN7EXAMPLE" in scan.lines
    assert ("users", "profile.aws_key", 1) in scan.locations


def test_bson_large_binary_field_becomes_a_blob_candidate(tmp_path):
    bson = pytest.importorskip("bson")
    from bson.binary import Binary
    p = tmp_path / "attachments.bson"
    payload = b"%PDF-1.4 " + b"x" * 100
    with open(p, "wb") as f:
        f.write(bson.encode({"_id": 1, "file": Binary(payload)}))
    scan = bson_peek.scan_contents(str(p))
    assert scan.ok
    assert any(data == payload for _, _, _, data in scan.blobs)


def test_bson_gracefully_unavailable_without_module(monkeypatch):
    monkeypatch.setattr(bson_peek, "_available", lambda: None)
    assert bson_peek.peek("whatever.bson")["error"] == "ImportError"
    scan = bson_peek.scan_contents("whatever.bson")
    assert not scan.ok


# ---------------------------------------------------------------- Access (mdbtools)

def test_mdb_reads_every_table_via_mdbtools(monkeypatch):
    class FakeProc:
        def __init__(self, stdout, returncode=0):
            self.stdout, self.returncode = stdout, returncode

    def fake_run(cmd, **kwargs):
        if cmd[0] == "mdb-tables":
            return FakeProc("users\n")
        if cmd[0] == "mdb-export" and cmd[2] == "users":
            return FakeProc("id,email,password\n1,alice@corp.com,hunter2hunter2!!\n")
        return FakeProc("", 1)

    monkeypatch.setattr(mdb_peek.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(mdb_peek.subprocess, "run", fake_run)

    assert mdb_peek.available()
    meta = mdb_peek.peek("fake.mdb")
    assert meta["tables"][0]["name"] == "users"
    assert "users.password" in meta["sensitive_columns"]

    scan = mdb_peek.scan_contents("fake.mdb")
    assert scan.ok
    assert "password=hunter2hunter2!!" in scan.lines


def test_mdb_falls_back_when_mdbtools_not_installed(monkeypatch):
    monkeypatch.setattr(mdb_peek.shutil, "which", lambda name: None)
    assert not mdb_peek.available()
    assert mdb_peek.peek("fake.mdb")["error"]
    assert not mdb_peek.scan_contents("fake.mdb").ok


# ---------------------------------------------------------------- registry dispatch

def test_registry_routes_by_extension_and_sqlite_by_content(tmp_path, monkeypatch):
    assert db_registry.engine_for(".dbf", None)[2] == "dbf-content"
    assert db_registry.engine_for(".bson", None)[2] == "bson-content"
    assert db_registry.engine_for(".xyz", "database")[2] == "sqlite-content"   # magic wins, any ext
    assert db_registry.engine_for(".unknownproprietary", None) is None        # no reader -> fallback

    monkeypatch.setattr(mdb_peek, "available", lambda: True)
    assert db_registry.engine_for(".accdb", None)[2] == "access-content"
    monkeypatch.setattr(mdb_peek, "available", lambda: False)
    assert db_registry.engine_for(".accdb", None) is None
