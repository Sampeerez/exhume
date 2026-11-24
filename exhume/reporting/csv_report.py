"""CSV output (for spreadsheets and remediation tracking)."""
from __future__ import annotations

import csv


def write_csv(payload: dict, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["severity", "verified", "detector", "path", "line", "value", "detail", "ai"])
        for h in payload["findings"]:
            w.writerow([
                h["severity_label"],
                {"live": "LIVE", "dead": "DEAD", "valid": "VALID",
                 "invalid": "INVALID"}.get(h["verified"], ""),
                h["detector"], h["path"], h["line"], h["value"], h.get("detail") or "", h.get("ai") or "",
            ])
