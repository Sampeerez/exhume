"""Scan configuration. Picklable dataclass (safe for multiprocessing).

Holds no non-serializable objects (no compiled regex, no file handles); rule
paths are passed as strings and each worker loads/compiles on demand.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Config:
    # --- Target & output ---
    target: str = "."
    output_prefix: str = "exhume_report"
    want_html: bool = True
    want_json: bool = False
    want_sarif: bool = False
    want_csv: bool = True
    open_report: bool = True

    # --- Scan scope ---
    max_size_mb: int = 100
    min_entropy: float = 3.8
    max_depth: int = 4
    archive_max_mb: int = 1024
    archive_max_files: int = 20000
    follow_links: bool = False
    scan_strings: bool = False
    ocr: bool = True            # OCR images when tesseract is available (auto-skips if not)
    db_peek: bool = True
    git_history: bool = True
    force_git: bool = False
    exclude: list[str] = field(default_factory=list)   # path globs to skip
    include: list[str] = field(default_factory=list)   # if set, only matching paths

    # --- Active verification ---
    probe_ips: bool = True      # with verify on: TCP-probe/reverse-DNS every discovered IP
    verify: bool = True         # verify credentials against provider APIs when possible
    only_verified: bool = False

    # --- Rules & allowlist ---
    rules_files: list[str] = field(default_factory=list)
    allowlist_file: str = ""
    no_default_rules: bool = False

    # --- Baseline (re-audit diffing) ---
    baseline_file: str = ""        # suppress findings already present here
    write_baseline_file: str = ""  # write current fingerprints here

    # --- Local AI triage (Ollama) ---
    ai: bool = True                # attempt local-AI triage if a model is reachable
    ai_model: str = ""             # specific model (blank = first available)
    ai_url: str = "http://localhost:11434"

    # --- Performance ---
    workers: int = 0            # 0 => auto
    use_processes: bool = True  # true multi-core
    file_timeout: int = 120     # seconds per entry (0 = no limit); avoids hangs on pathological files

    # --- Presentation ---
    show_per_type: int = 8
    min_sev: str = "all"        # all|medium|high|critical
    no_color: bool = False
    context_width: int = 64     # chars on each side of the match in the context
    html_max: int = 50000       # max findings embedded in the HTML report (0 = all)
    mask: bool = False          # mask secret values (for client-facing reports)

    # --- Dependencies ---
    autoinstall: bool = True

    # --- SMB ---
    smb_user: str = ""
    smb_pass: str = ""
    smb_domain: str = ""
    smb_port: int = 445
    smb_all: bool = False

    # --- S3 ---
    s3_region: str = ""
    s3_all: bool = False

    def resolved_workers(self) -> int:
        if self.workers and self.workers > 0:
            return self.workers
        cpu = os.cpu_count() or 4
        return cpu if self.use_processes else min(32, cpu * 4)

    @property
    def max_bytes(self) -> int:
        return self.max_size_mb * 1024 * 1024

    def apply_profile(self, quick: bool = False, deep: bool = False) -> None:
        if quick:
            self.max_depth = min(self.max_depth, 2)
            self.scan_strings = False
            self.ocr = False
            self.max_size_mb = min(self.max_size_mb, 25)
        if deep:
            self.scan_strings = True
            self.ocr = True
            self.max_depth = max(self.max_depth, 6)
            self.max_size_mb = max(self.max_size_mb, 300)
