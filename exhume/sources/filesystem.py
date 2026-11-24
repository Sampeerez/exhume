"""Filesystem traversal with optional path-glob filtering."""
from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterator, Sequence

from ..extractors.magic import DEFAULT_SKIP_DIRS


def _matches(path: str, patterns: Sequence[str]) -> bool:
    name = os.path.basename(path)
    return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(name, p) for p in patterns)


def iter_dir(root: str, follow_links: bool = False,
             exclude: Sequence[str] = (), include: Sequence[str] = ()) -> Iterator[str]:
    """Yield file paths under *root*, skipping noisy dirs and .git.

    *exclude*: glob patterns to skip. *include*: if non-empty, only paths matching
    one of these globs are yielded.
    """
    skip = set(DEFAULT_SKIP_DIRS)
    skip.add(".git")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_links):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            if exclude and _matches(path, exclude):
                continue
            if include and not _matches(path, include):
                continue
            yield path
