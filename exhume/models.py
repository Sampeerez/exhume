"""Domain data models (picklable dataclasses for multiprocessing)."""
from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    """Finding severity. The integer value allows sorting and comparison."""
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3

    @property
    def label(self) -> str:
        return {1: "MEDIUM", 2: "HIGH", 3: "CRITICAL"}[int(self)]


class Verified(enum.Enum):
    """Result of active credential verification."""
    LIVE = "live"          # confirmed valid against the provider API
    DEAD = "dead"          # rejected by the provider (401/403)
    UNKNOWN = "unknown"    # could not be determined (no network, no verifier)
    VALID = "valid"        # non-credential data confirmed real (checksum OK / host answers)
    INVALID = "invalid"    # non-credential data that failed its check (bad checksum / no host)


@dataclass
class Finding:
    """A single secret or sensitive-data finding."""
    detector: str                      # name of the detector that fired
    severity: Severity
    line: int
    redacted: str                      # masked value (used with --mask)
    context: str                       # surrounding snippet (windowed, raw)
    path: str = ""                     # display path (filled in when aggregated)
    col: int = 0                       # column (char offset) of the match in its line
    context_block: list = field(default_factory=list)  # [[lineno, text], ...] around the match
    verifier: str | None = None        # key in VERIFIERS, if applicable
    verified: Verified = Verified.UNKNOWN
    detail: str | None = None          # verification detail or note
    ai_verdict: str | None = None      # local-AI judgement: "real" | "false" | None (not judged)
    ai_note: str | None = None         # how the verdict was reached
    # Plaintext secret: NEVER serialized to the report by default; lives in memory
    # for verification and is only exposed when the user passes --reveal.
    secret: str | None = field(default=None, repr=False)
    # Transient auxiliary data (e.g. AWS secret-key candidates). Not serialized.
    extra: dict = field(default_factory=dict, repr=False)

    @property
    def hidden(self) -> bool:
        """Failed its check or judged a false positive by the local AI (kept, but not shown by default)."""
        return self.verified is Verified.INVALID or self.ai_verdict == "false"

    def fingerprint(self) -> str:
        """Stable identifier for baseline diffing (does not expose the secret)."""
        basis = self.secret if self.secret else self.redacted
        digest = hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]
        # Line is intentionally excluded so edits that shift lines don't break the match.
        return f"{self.detector}|{self.path}|{digest}"

    def value_fingerprint(self) -> str:
        """Identity of the (detector, value) PAIR, ignoring path/line — used to collapse the
        same secret or PII value seen in many places into a single reported entry."""
        basis = self.secret if self.secret else self.redacted
        return hashlib.sha256(f"{self.detector}|{basis}".encode("utf-8", "replace")).hexdigest()[:16]

    def _mask(self, text: str) -> str:
        return text.replace(self.secret, self.redacted) if self.secret and text else text

    def to_public_dict(self) -> dict[str, Any]:
        """Masked dict for reports (never contains the plaintext secret)."""
        return {
            "detector": self.detector,
            "severity": int(self.severity),
            "severity_label": self.severity.label,
            "line": self.line,
            "col": self.col,
            "value": self.redacted,
            "context": self._mask(self.context),
            "context_block": [[n, self._mask(t)] for n, t in self.context_block],
            "path": self.path,
            "verified": self.verified.value,
            "detail": self.detail,
            "fingerprint": self.fingerprint(),
        }


@dataclass
class FileResult:
    """Result of analyzing one entry (file, blob, etc.)."""
    path: str
    name: str
    ext: str
    size: int
    tags: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    note: str | None = None
    method: str | None = None
    db_info: dict | None = None
    ai_verdict: str | None = None   # local-AI judgement of an asset: "real" | "false" | None

    @property
    def interesting(self) -> bool:
        return bool(self.findings or self.tags or self.note or self.db_info)


@dataclass
class ScanStats:
    root: str = ""
    seen: int = 0
    scanned: int = 0
    nested: int = 0
    git_blobs: int = 0
    elapsed: float = 0.0
    verified_live: int = 0
    suppressed: int = 0   # findings hidden by the baseline
    ai_summary: str = ""  # local-AI triage report (Markdown), if available
    ai_model: str = ""    # model that produced the triage
    coverage: dict = field(default_factory=dict)  # how every entry was handled
    ai_filter: dict = field(default_factory=dict)  # local-AI judgement counters
    ai_engine: str = ""


def finding_sort_key(f: Finding) -> tuple:
    """Sort: live credentials first, then by severity, then by path."""
    return (f.verified is not Verified.LIVE, f.hidden, -int(f.severity), f.path, f.line)


@dataclass
class FindingGroup:
    """Every occurrence of the same (detector, value) pair, collapsed into one entry.

    A password or an email address pasted into 30 files is one real-world fact to fix,
    not 30 — the report shows it once, with every place it was found.
    """
    rep: Finding                                        # representative occurrence (first seen)
    locations: list[tuple[str, int, int]] = field(default_factory=list)  # (path, line, col)

    @property
    def count(self) -> int:
        return len(self.locations)

    @property
    def fingerprint(self) -> str:
        return self.rep.value_fingerprint()


def group_findings(findings: list[Finding]) -> list[FindingGroup]:
    """Collapse findings that share a detector + value into one :class:`FindingGroup` each,
    preserving first-seen order. All occurrences of the same value already carry identical
    severity/verified/ai_verdict (those are computed from the value itself), so the first
    occurrence can safely stand in for the group."""
    groups: dict[str, FindingGroup] = {}
    order: list[str] = []
    for f in findings:
        key = f.value_fingerprint()
        g = groups.get(key)
        if g is None:
            g = FindingGroup(rep=f)
            groups[key] = g
            order.append(key)
        g.locations.append((f.path, f.line, f.col))
    return [groups[k] for k in order]


def group_sort_key(g: FindingGroup) -> tuple:
    """Like :func:`finding_sort_key`, but a value seen in more places sorts first within
    its severity tier — it's the more urgent one to fix."""
    f = g.rep
    return (f.verified is not Verified.LIVE, f.hidden, -int(f.severity), -g.count, f.path, f.line)
