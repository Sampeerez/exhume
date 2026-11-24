"""Loading custom rules from YAML/JSON files and allowlist.

Rule format (YAML or JSON)::

    rules:
      - name: "ACME internal key"
        regex: "ACME-[0-9A-F]{32}"
        severity: critical        # critical|high|medium
        entropy: false            # optional
        anchors: ["acme-"]        # optional, speeds up prefiltering
    allowlist:
      - "EXAMPLE"                  # regex; a matching line is ignored

Lets each client/audit keep its own rule set without touching the code.
"""
from __future__ import annotations

import json
import os
import re
from functools import lru_cache

from ..models import Severity
from .patterns import Detector

_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM}


def _load_structured(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
            return yaml.safe_load(text) or {}
        except Exception as exc:  # pragma: no cover - depends on PyYAML
            raise RuntimeError(f"Could not read YAML '{path}' (is PyYAML installed?): {exc}") from exc
    return json.loads(text) if text.strip() else {}


def load_custom_detectors(rules_files: list[str]) -> list[Detector]:
    """Compile user-defined detectors. Invalid rules are skipped."""
    out: list[Detector] = []
    for path in rules_files:
        if not path or not os.path.isfile(path):
            continue
        data = _load_structured(path)
        for raw in data.get("rules", []) or []:
            try:
                name = str(raw["name"])
                rx = re.compile(raw["regex"])
            except (KeyError, re.error):
                continue
            sev = _SEV.get(str(raw.get("severity", "high")).lower(), Severity.HIGH)
            anchors = tuple(str(a).lower() for a in raw.get("anchors", []) or [])
            out.append(Detector(name, rx, sev, bool(raw.get("entropy", False)), None, anchors))
    return out


def load_allowlist(rules_files: list[str], allowlist_file: str) -> re.Pattern | None:
    """Combine allowlist patterns (from --allowlist and from the rules files)."""
    patterns: list[str] = []
    if allowlist_file and os.path.isfile(allowlist_file):
        with open(allowlist_file, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    for path in rules_files:
        if path and os.path.isfile(path):
            try:
                for pat in _load_structured(path).get("allowlist", []) or []:
                    patterns.append(str(pat))
            except Exception:
                continue
    valid = []
    for p in patterns:
        try:
            re.compile(p)
            valid.append(p)
        except re.error:
            continue
    return re.compile("|".join(f"(?:{p})" for p in valid)) if valid else None


@lru_cache(maxsize=8)
def cached_rules(rules_key: tuple[str, ...], allowlist_file: str):
    """Per-process cache (hashable key) to avoid recompiling for every file."""
    detectors = load_custom_detectors(list(rules_key))
    allow = load_allowlist(list(rules_key), allowlist_file)
    return detectors, allow
