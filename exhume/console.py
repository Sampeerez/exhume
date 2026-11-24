"""Console output: ANSI colors with automatic disabling."""
from __future__ import annotations

import sys


class Colors:
    R = "\033[31m"
    G = "\033[32m"
    Y = "\033[33m"
    B = "\033[34m"
    M = "\033[35m"
    CY = "\033[36m"
    W = "\033[37m"
    GR = "\033[90m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"
    _enabled = True

    @classmethod
    def disable(cls) -> None:
        cls._enabled = False
        for k in list(vars(cls)):
            v = getattr(cls, k)
            if k.isupper() and isinstance(v, str) and v.startswith("\033"):
                setattr(cls, k, "")

    @classmethod
    def auto(cls, no_color: bool) -> None:
        if no_color or not sys.stdout.isatty():
            cls.disable()


def eprint(*args, **kwargs) -> None:
    """Print to stderr (progress/warnings), separate from the data output."""
    kwargs.setdefault("file", sys.stderr)
    print(*args, **kwargs)
