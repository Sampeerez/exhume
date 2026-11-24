"""Data sources: filesystem, git history, SMB, Docker, S3."""
from __future__ import annotations

from .filesystem import iter_dir
from .git_history import is_git_repo, iter_git_blobs

__all__ = ["iter_dir", "iter_git_blobs", "is_git_repo"]
