"""Report generation in several formats."""
from __future__ import annotations

import os

from ..config import Config
from ..models import FileResult, ScanStats
from .console import print_report
from .csv_report import write_csv
from .html import write_html
from .json_report import build_payload, write_json
from .sarif import write_sarif

__all__ = ["print_report", "write_outputs", "build_payload"]


def write_outputs(results: list[FileResult], stats: ScanStats, cfg: Config) -> list[str]:
    """Escribe los formatos solicitados y devuelve las rutas generadas."""
    written: list[str] = []
    payload = build_payload(results, stats, mask=cfg.mask)

    if cfg.want_json:
        p = cfg.output_prefix + ".json"
        write_json(payload, p)
        written.append(p)
    if cfg.want_csv:
        p = cfg.output_prefix + ".csv"
        write_csv(payload, p)
        written.append(p)
    if cfg.want_sarif:
        p = cfg.output_prefix + ".sarif"
        write_sarif(payload, p)
        written.append(p)
    if cfg.want_html:
        p = cfg.output_prefix + ".html"
        write_html(payload, p)
        written.append(p)
        if cfg.open_report:
            try:
                import webbrowser
                webbrowser.open("file://" + os.path.abspath(p))
            except Exception:
                pass
    return written
