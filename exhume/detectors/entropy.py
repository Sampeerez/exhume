"""Shannon entropy and number validation (Luhn)."""
from __future__ import annotations

import math
import re
from collections import Counter

_NON_DIGIT = re.compile(r"\D")


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char. Useful for spotting random-looking strings."""
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def luhn_valid(number: str) -> bool:
    """Validate a number with the Luhn algorithm (credit cards)."""
    digits = [int(c) for c in _NON_DIGIT.sub("", number)]
    if len(digits) < 13:
        return False
    odd = digits[-1::-2]
    even = digits[-2::-2]
    total = sum(odd) + sum(sum(divmod(d * 2, 10)) for d in even)
    return total % 10 == 0
