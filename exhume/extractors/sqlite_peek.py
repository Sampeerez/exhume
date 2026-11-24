"""Read-only inspection of SQLite databases."""
from __future__ import annotations

import re
import sqlite3

SENSITIVE_COL = re.compile(
    r"(?i)(pass|pwd|secret|token|hash|salt|credit|card|cvv|iban|ssn|dni|"
    r"email|phone|tele|api|key|auth|session|cookie)"
)


def peek(path: str, max_tables: int = 200) -> dict:
    """List tables, row counts and suspicious columns without modifying the file."""
    info: dict = {"tables": [], "sensitive_columns": []}
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True, timeout=2)
    except Exception as exc:
        info["error"] = type(exc).__name__
        return info
    try:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()][:max_tables]
        for t in tables:
            try:
                cur.execute(f'SELECT COUNT(*) FROM "{t}"')
                rows = cur.fetchone()[0]
            except Exception:
                rows = None
            cols = []
            try:
                cur.execute(f'PRAGMA table_info("{t}")')
                cols = [c[1] for c in cur.fetchall()]
            except Exception:
                pass
            info["tables"].append({"name": t, "rows": rows, "columns": cols})
            for col in cols:
                if SENSITIVE_COL.search(col):
                    info["sensitive_columns"].append(f"{t}.{col}")
    except Exception as exc:
        info["error"] = type(exc).__name__
    finally:
        con.close()
    return info
