"""CSV output (for spreadsheets and remediation tracking)."""
from __future__ import annotations

import csv

_LOC_CAP = 15  # locations listed inline before "(+N more)"; occurrences is never capped


def _locations_str(locs: list[dict]) -> str:
    shown = locs[:_LOC_CAP]
    s = "; ".join(f"{loc['path']}:{loc['line']}" for loc in shown)
    extra = len(locs) - len(shown)
    return f"{s} (+{extra} more)" if extra > 0 else s


def write_csv(payload: dict, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["severity", "verified", "detector", "occurrences", "path", "line",
                   "value", "detail", "ai", "locations"])
        for h in payload["findings"]:
            w.writerow([
                h["severity_label"],
                {"live": "LIVE", "dead": "DEAD", "valid": "VALID",
                 "invalid": "INVALID"}.get(h["verified"], ""),
                h["detector"], h.get("occurrences", 1), h["path"], h["line"], h["value"],
                h.get("detail") or "", h.get("ai") or "", _locations_str(h.get("locations") or []),
            ])
