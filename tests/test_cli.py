"""Tests for the CLI's argument handling."""
from __future__ import annotations

from exhume.cli import args_to_config, build_parser, derive_output_prefix


def test_derive_output_prefix_from_folder(tmp_path):
    share = tmp_path / "copia_shares"
    share.mkdir()
    assert derive_output_prefix(str(share)) == "copia_shares_exhume_report"
    assert derive_output_prefix(str(share) + "/") == "copia_shares_exhume_report"


def test_derive_output_prefix_from_file(tmp_path):
    f = tmp_path / "backup.zip"
    f.write_text("x")
    assert derive_output_prefix(str(f)) == "backup_exhume_report"


def test_derive_output_prefix_sanitizes_unsafe_characters():
    assert derive_output_prefix("/abs/path/My Share!!") == "My_Share_exhume_report"


def test_derive_output_prefix_strips_remote_schemes():
    assert derive_output_prefix("smb://10.0.0.5/Finance") == "Finance_exhume_report"
    assert derive_output_prefix("docker://myapp:latest") == "myapp_latest_exhume_report"
    assert derive_output_prefix("s3://my-bucket/logs") == "logs_exhume_report"


def test_derive_output_prefix_falls_back_when_nothing_usable():
    assert derive_output_prefix("///") == "exhume_report"


def test_cli_uses_derived_prefix_by_default(tmp_path):
    share = tmp_path / "copia_shares"
    share.mkdir()
    parser = build_parser()
    cfg = args_to_config(parser.parse_args([str(share)]))
    assert cfg.output_prefix == "copia_shares_exhume_report"


def test_cli_respects_explicit_output_flag(tmp_path):
    share = tmp_path / "copia_shares"
    share.mkdir()
    parser = build_parser()
    cfg = args_to_config(parser.parse_args([str(share), "-o", "custom_name"]))
    assert cfg.output_prefix == "custom_name"
