"""Tests for the Git history scan."""
from __future__ import annotations

from exhume.sources.git_history import is_git_repo, iter_git_blobs


def test_detects_repo(git_repo):
    assert is_git_repo(str(git_repo))


def test_finds_deleted_secret_in_history(git_repo):
    blobs = list(iter_git_blobs(str(git_repo)))
    contents = b"\n".join(b for _, _, b in blobs)
    # The secret was deleted from the tree but remains in history
    assert b"AKIAIOSFODNN7EXAMPLE" in contents


def test_scanner_reports_git_history(git_repo, cfg):
    from exhume import Scanner
    cfg.target = str(git_repo)
    results = Scanner(cfg).run()
    git_findings = [f for r in results if "git_history" in r.tags for f in r.findings]
    assert any(f.detector == "AWS Access Key ID" for f in git_findings)
