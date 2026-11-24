"""Secret detection engine over text."""
from __future__ import annotations

import re

from ..models import Finding, Severity
from .entropy import shannon_entropy
from .patterns import (
    AWS_SECRET_RE,
    DETECTORS,
    ENTROPY_DENY,
    GENERIC_SECRET,
    Detector,
    is_placeholder,
)
from .rules import cached_rules, load_allowlist, load_custom_detectors
from .validators import VALIDATORS

__all__ = [
    "scan_text",
    "aws_secret_candidates",
    "DETECTORS",
    "AWS_SECRET_RE",
    "VALIDATORS",
    "load_custom_detectors",
    "load_allowlist",
    "cached_rules",
    "Detector",
]

_MAX_LINE = 8000
DEFAULT_CONTEXT = 64
_BLOCK_BEFORE = 3     # context lines before the match
_BLOCK_AFTER = 3      # context lines after the match
_BLOCK_LINE_CAP = 400

# Values that look like CODE rather than a real secret literal. Used to drop
# false positives such as `password = req.body.password` or `pwd = getEnv("X")`.
_CODE_REF = re.compile(
    r"""^(?:
        (?:req|request|process|os|self|this|cls|config|cfg|env|settings|params|
           data|body|form|args|kwargs|ctx|context|opts|options|props|state|store|
           input|event|e|err|error|res|response|row|record|item|obj|model|user|
           db|conn|session|window|document|global|globals|locals)[\.\[] |   # x.y / x[
        [A-Za-z_][\w]*\s*\(                                                  # a call(
    )""",
    re.VERBOSE,
)
_CODE_TOKENS = {
    "str", "string", "int", "integer", "bool", "boolean", "number", "float",
    "none", "null", "nil", "undefined", "true", "false", "object", "dict",
    "list", "array", "any", "void", "self", "this", "value", "field", "input",
    "password", "passwd", "pwd", "pass", "secret", "token", "apikey", "api_key",
    "varchar", "text", "char", "nvarchar", "default", "required", "optional",
}


def _looks_like_code(value: str) -> bool:
    """True if the captured value is a code reference/expression, not a real secret."""
    v = value.strip().strip("'\"")
    if not v:
        return True
    low = v.lower()
    if low in _CODE_TOKENS:
        return True
    if _CODE_REF.match(v):
        return True
    # Templates / interpolation / expressions
    if any(tok in v for tok in ("${", "{{", "<%", "%(", "))", "](", "+ ", " +")):
        return True
    # A bare identifier that is clearly a variable name (snake/camel, no entropy)
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,30}", v) and shannon_entropy(v) < 2.6:
        return True
    return False


def _redact(value: str, keep: int = 4) -> str:
    value = value.strip()
    if len(value) <= keep * 2:
        return (value[0] + "***") if value else "***"
    return f"{value[:keep]}...{value[-keep:]} (len {len(value)})"


def _snippet(line: str, start: int, end: int, width: int) -> str:
    """Window centered on the match, with ellipses at the edges.

    Solves the "grep" problem: on a huge line (minified JS, a pasted dump...) it
    shows ONLY the immediate surroundings of the match, not the whole text around it.
    """
    s = max(0, start - width)
    e = min(len(line), end + width)
    frag = line[s:e].strip()
    prefix = "…" if s > 0 else ""
    suffix = "…" if e < len(line) else ""
    return f"{prefix}{frag}{suffix}"


def _block(lines: list[str], idx: int) -> list[list]:
    """Return [[lineno, text], ...] for the lines surrounding match at 0-based idx."""
    lo = max(0, idx - _BLOCK_BEFORE)
    hi = min(len(lines), idx + _BLOCK_AFTER + 1)
    out = []
    for n in range(lo, hi):
        t = lines[n]
        if len(t) > _BLOCK_LINE_CAP:
            t = t[:_BLOCK_LINE_CAP] + "…"
        out.append([n + 1, t])
    return out


def scan_text(
    text: str,
    min_entropy: float,
    allow: re.Pattern | None = None,
    extra_detectors: tuple[Detector, ...] = (),
    use_builtin: bool = True,
    context_width: int = DEFAULT_CONTEXT,
) -> list[Finding]:
    """Scan text line by line and return findings.

    Combines built-in and custom detectors, prefilters by literal anchors,
    validates each match (real IPs/URLs/cards), drops code-reference false
    positives, captures a windowed snippet plus surrounding lines, deduplicates
    overlaps and adds a generic high-entropy pass. Context is stored RAW; masking
    (for --mask) is applied at report time.
    """
    findings: list[Finding] = []
    detectors = (DETECTORS if use_builtin else []) + list(extra_detectors)
    lines = text.splitlines()

    for idx, raw_line in enumerate(lines):
        lineno = idx + 1
        line = raw_line[:_MAX_LINE] if len(raw_line) > _MAX_LINE else raw_line
        if allow is not None and allow.search(line):
            continue
        lower = line.lower()

        for det in detectors:
            if det.anchors and not any(a in lower for a in det.anchors):
                continue
            for m in det.regex.finditer(line):
                i = m.lastindex or 0
                value = m.group(i) if i else m.group(0)
                if not value:
                    continue
                if det.validator:
                    vfn = VALIDATORS.get(det.validator)
                    if vfn and not vfn(value):
                        continue
                if det.needs_entropy:
                    if (shannon_entropy(value) < (min_entropy - 1.0)
                            or is_placeholder(value) or _looks_like_code(value)):
                        continue
                start, end = (m.span(i) if i else m.span(0))
                findings.append(Finding(
                    detector=det.name, severity=det.severity, line=lineno, col=start + 1,
                    redacted=_redact(value), context=_snippet(line, start, end, context_width),
                    context_block=_block(lines, idx), verifier=det.verifier, secret=value,
                ))

        if not ENTROPY_DENY.search(line):
            for m in GENERIC_SECRET.finditer(line):
                cand = m.group(1)
                if len(cand) < 24:
                    continue
                ent = shannon_entropy(cand)
                if ent >= min_entropy and re.search(r"[A-Za-z]", cand) and re.search(r"\d", cand):
                    if any(f.line == lineno and cand[:8] in f.redacted for f in findings):
                        continue
                    start, end = m.span(1)
                    findings.append(Finding(
                        detector=f"High-entropy string ({ent:.1f})", severity=Severity.MEDIUM,
                        line=lineno, col=start + 1, redacted=_redact(cand),
                        context=_snippet(line, start, end, context_width),
                        context_block=_block(lines, idx), secret=cand,
                    ))

    return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Remove overlaps: same secret on the same line matched by several rules.

    Keeps the most useful one: first any with a verifier, then higher severity.
    """
    best: dict[tuple[int, str], Finding] = {}
    order: list[tuple[int, str]] = []
    for f in findings:
        key = (f.line, f.secret or f.redacted)
        cur = best.get(key)
        if cur is None:
            best[key] = f
            order.append(key)
            continue
        if (f.verifier is not None, int(f.severity)) > (cur.verifier is not None, int(cur.severity)):
            best[key] = f
    return [best[k] for k in order]


def aws_secret_candidates(text: str, limit: int = 8) -> list[str]:
    """Return possible AWS secret keys (40 chars) present in the text."""
    seen: list[str] = []
    for m in AWS_SECRET_RE.finditer(text):
        v = m.group(0)
        if v not in seen:
            seen.append(v)
            if len(seen) >= limit:
                break
    return seen
