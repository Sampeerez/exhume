"""SARIF 2.1.0 output (GitHub code scanning, DefectDojo, etc.)."""
from __future__ import annotations

import json
import re

from .. import __version__

_LEVEL = {3: "error", 2: "warning", 1: "note"}


def write_sarif(payload: dict, path: str) -> None:
    rules: dict[str, dict] = {}
    results = []
    for h in payload["findings"]:
        rid = re.sub(r"[^A-Za-z0-9]+", "_", h["detector"])[:60]
        rules.setdefault(rid, {"id": rid, "name": h["detector"],
                               "shortDescription": {"text": h["detector"]}})
        occ = h.get("occurrences", 1)
        msg = f"{h['detector']} — {h['value']}"
        if occ > 1:
            msg += f" (seen in {occ} places)"
        if h.get("detail"):
            msg += f" [{h['detail']}]"
        # One value seen in several files becomes one result with several locations,
        # instead of a separate (and separately-triaged) result per occurrence.
        locs = h.get("locations") or [{"path": h["path"], "line": h["line"]}]
        results.append({
            "ruleId": rid,
            "level": _LEVEL[h["severity"]],
            "message": {"text": msg},
            "partialFingerprints": {"exhume/v1": h["fingerprint"]},
            "properties": {"verified": h["verified"], "occurrences": occ},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": loc["path"].split(" ::> ")[0].replace(" ", "%20")},
                "region": {"startLine": max(1, loc["line"])},
            }} for loc in locs],
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "exhume",
                "version": __version__,
                "informationUri": "https://github.com/Sampeerez/exhume",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
