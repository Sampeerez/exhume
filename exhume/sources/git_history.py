"""Full Git history scan.

Enumera todos los blobs alcanzables (`git rev-list --objects --all`) y recupera
their content with `git cat-file --batch`, deduplicating by SHA. This finds
secrets deleted from the working tree but still present in old commits.
"""
from __future__ import annotations

import os
import subprocess
from collections.abc import Iterator


def is_git_repo(path: str) -> bool:
    return os.path.isdir(os.path.join(path, ".git"))


def iter_git_blobs(repo: str, timeout: int = 300) -> Iterator[tuple[str, str, bytes]]:
    """Yield (sha, logical_path, content) for each unique blob in history."""
    try:
        rl = subprocess.run(
            ["git", "-C", repo, "rev-list", "--objects", "--all"],
            capture_output=True, text=True, timeout=min(timeout, 120),
        )
    except Exception:
        return
    if rl.returncode != 0:
        return

    sha_path: dict[str, str] = {}
    for line in rl.stdout.splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[1]:
            sha_path[parts[0]] = parts[1]
    if not sha_path:
        return

    try:
        proc = subprocess.Popen(
            ["git", "-C", repo, "cat-file", "--batch"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )
        payload = ("\n".join(sha_path.keys()) + "\n").encode()
        data, _ = proc.communicate(payload, timeout=timeout)
    except Exception:
        return

    i, n = 0, len(data)
    while i < n:
        nl = data.find(b"\n", i)
        if nl < 0:
            break
        header = data[i:nl].decode("utf-8", "replace").split(" ")
        i = nl + 1
        if len(header) != 3 or header[1] != "blob":
            continue
        sha, size = header[0], int(header[2])
        blob = data[i:i + size]
        i += size + 1  # +1 for the trailing newline of the batch record
        if sha in sha_path:
            yield sha, sha_path[sha], blob
