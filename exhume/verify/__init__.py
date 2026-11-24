"""Active credential verification against provider APIs."""
from __future__ import annotations

from .verifiers import VERIFIERS, verify_aws_pair, verify_single

__all__ = ["VERIFIERS", "verify_single", "verify_aws_pair"]
