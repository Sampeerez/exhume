"""Shared fixtures for the test suite."""
from __future__ import annotations

import subprocess

import pytest

from exhume.config import Config


@pytest.fixture
def cfg(tmp_path) -> Config:
    """Fast, deterministic config for tests (threads, no network, no autoinstall)."""
    return Config(
        target=str(tmp_path),
        use_processes=False,
        autoinstall=False,
        want_html=False,
        open_report=False,
        want_csv=False,
        verify=False,
    )


@pytest.fixture
def git_repo(tmp_path):
    """Create a git repo with a committed secret that is then deleted from the tree."""
    repo = tmp_path / "repo"
    repo.mkdir()

    def run(*args):
        subprocess.run(["git", "-C", str(repo), *args], check=True,
                       capture_output=True)

    run("init", "-q")
    run("config", "user.email", "t@t.t")
    run("config", "user.name", "t")
    (repo / "leak.txt").write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
    (repo / "keep.txt").write_text("contenido normal\n")
    run("add", "-A")
    run("commit", "-qm", "con secreto")
    (repo / "leak.txt").unlink()
    run("add", "-A")
    run("commit", "-qm", "borrado")
    return repo
