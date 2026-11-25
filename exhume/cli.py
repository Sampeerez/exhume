"""Exhume command-line interface."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .config import Config
from .console import Colors, eprint
from .deps import resolve
from .reporting import print_report, write_outputs
from .scanner import Scanner

_BANNER = "  exhume · secrets discovery & verification\n"

_EPILOG = """\
Examples:
  exhume /mnt/share                        # scans + verifies live credentials by default
  exhume . --git --only-verified           # repo + history, show only live creds
  exhume smb://10.0.0.5/Finance --smb-user audit --smb-pass '***'
  exhume docker://myapp:latest --sarif
  exhume s3://my-bucket/logs
  exhume backup.zip --strings --ocr --rules client_rules.yaml
  exhume . --baseline known.json           # only show NEW findings
  exhume . --mask                          # client-safe: hide secret values
  exhume . --no-verify                     # don't touch provider APIs

For AUTHORIZED audits only. Verification (on by default) authenticates using the
discovered credentials; findings that can't be verified are still reported.
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="exhume",
        description=f"Exhume v{__version__} — sensitive-data discovery and verification.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=_EPILOG,
    )
    p.add_argument("target", help="Folder, SMB (mounted or smb://), docker://img, s3://bucket, file or git repo")
    p.add_argument("-o", "--output", default="exhume_report", help="Output file prefix")
    p.add_argument("--version", action="version", version=f"exhume {__version__}")

    out = p.add_argument_group("output")
    out.add_argument("--json", action="store_true")
    out.add_argument("--sarif", action="store_true")
    out.add_argument("--csv", action="store_true", help=argparse.SUPPRESS)  # CSV is on by default
    out.add_argument("--no-csv", action="store_true", help="Do not write the CSV with every finding")
    out.add_argument("--no-html", action="store_true")
    out.add_argument("--open", action="store_true", help=argparse.SUPPRESS)  # open is on by default
    out.add_argument("--no-open", action="store_true", help="Do not open the HTML report when done")
    out.add_argument("--show", type=int, default=8, help="Examples per type in console output")
    out.add_argument("--min-sev", choices=["all", "medium", "high", "critical"], default="all")
    out.add_argument("--context", type=int, default=64,
                     help="Context chars on each side of the match (def 64; 0 = value only)")
    out.add_argument("--mask", action="store_true",
                     help="Mask secret values (client-safe report). Default shows REAL values.")
    out.add_argument("--no-color", action="store_true")

    scope = p.add_argument_group("scope")
    scope.add_argument("--max-size", type=int, default=100, help="Max MB per file (def 100)")
    scope.add_argument("--min-entropy", type=float, default=3.8)
    scope.add_argument("--max-depth", type=int, default=4, help="Nested-archive depth")
    scope.add_argument("--archive-max-mb", type=int, default=1024)
    scope.add_argument("--archive-max-files", type=int, default=20000)
    scope.add_argument("--strings", action="store_true", help="Scan strings inside ALL binaries")
    scope.add_argument("--no-ocr", dest="ocr", action="store_false",
                       help="Disable image OCR (on by default when tesseract is available)")
    scope.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                       help="Path glob to skip (repeatable), e.g. '*.min.js'")
    scope.add_argument("--include", action="append", default=[], metavar="GLOB",
                       help="If set, only scan paths matching these globs (repeatable)")
    scope.add_argument("--no-db-peek", dest="db_peek", action="store_false",
                       help="Don't open databases to list tables or scan row data for secrets")
    scope.add_argument("--db-max-rows", type=int, default=5000,
                       help="Rows sampled per table when scanning database content (def 5000)")
    scope.add_argument("--follow-links", action="store_true")
    scope.add_argument("--quick", action="store_true", help="Fast profile")
    scope.add_argument("--deep", action="store_true", help="Exhaustive profile (strings+ocr+depth)")

    git = p.add_argument_group("git")
    git.add_argument("--git", action="store_true", help="Force git-history scan")
    git.add_argument("--no-git-history", dest="git_history", action="store_false")

    ver = p.add_argument_group("verification")
    ver.add_argument("--no-verify", dest="verify", action="store_false",
                     help="Disable live verification (on by default; unverifiable findings are still reported)")
    ver.add_argument("--no-ip-probe", dest="probe_ips", action="store_false",
                     help="Do not TCP-probe / reverse-resolve discovered IPs to check they are real hosts")
    ver.add_argument("--only-verified", action="store_true", help="Show only LIVE credentials")

    rules = p.add_argument_group("rules & baseline")
    rules.add_argument("--rules", action="append", default=[], metavar="FILE",
                       help="YAML/JSON rules file (repeatable)")
    rules.add_argument("--allowlist", default="", help="File with regexes to ignore")
    rules.add_argument("--no-default-rules", action="store_true", help="Use only custom rules")
    rules.add_argument("--baseline", default="", metavar="FILE",
                       help="Suppress findings already present in this baseline")
    rules.add_argument("--write-baseline", default="", metavar="FILE",
                       help="Write current fingerprints to this baseline file")

    ai = p.add_argument_group("local AI (bundled model, Ollama fallback)")
    ai.add_argument("--no-ai", dest="ai", action="store_false",
                    help="Disable the local AI (match judging, asset filtering and triage summary)")
    ai.add_argument("--ai-model", default="", help="Ollama model to use (default: first available)")
    ai.add_argument("--ai-gguf", default="", help="Use this .gguf model file for the bundled AI")
    ai.add_argument("--ai-max-calls", type=int, default=4000,
                    help="Max model calls spent judging ambiguous matches (default 4000)")
    ai.add_argument("--ai-url", default="http://localhost:11434", help="Ollama base URL")

    p.add_argument("--html-max", type=int, default=50000,
                   help="Max findings embedded in the HTML report, highest severity first (0=all; "
                        "extra findings go to an auto-written CSV)")
    perf = p.add_argument_group("performance")
    perf.add_argument("--workers", type=int, default=0, help="Worker count (0=auto)")
    perf.add_argument("--file-timeout", type=int, default=120,
                      help="Max seconds per file before skipping it (0=no limit)")
    perf.add_argument("--threads", action="store_true", help="Use threads instead of processes")
    perf.add_argument("--no-autoinstall", dest="autoinstall", action="store_false")

    smb = p.add_argument_group("smb")
    smb.add_argument("--smb-user", default="")
    smb.add_argument("--smb-pass", default="")
    smb.add_argument("--smb-domain", default="")
    smb.add_argument("--smb-port", type=int, default=445)
    smb.add_argument("--smb-all", action="store_true", help="Also download large files")

    s3 = p.add_argument_group("s3")
    s3.add_argument("--s3-region", default="")
    s3.add_argument("--s3-all", action="store_true")

    p.set_defaults(db_peek=True, git_history=True, autoinstall=True, ocr=True, ai=True, verify=True)
    return p


def args_to_config(a: argparse.Namespace) -> Config:
    cfg = Config(
        target=a.target, output_prefix=a.output,
        want_html=not a.no_html, want_json=a.json, want_sarif=a.sarif, want_csv=not a.no_csv,
        open_report=not a.no_open, max_size_mb=a.max_size, min_entropy=a.min_entropy,
        max_depth=a.max_depth, archive_max_mb=a.archive_max_mb, archive_max_files=a.archive_max_files,
        follow_links=a.follow_links, scan_strings=a.strings, ocr=a.ocr, db_peek=a.db_peek,
        db_max_rows=a.db_max_rows,
        git_history=a.git_history, force_git=a.git, exclude=list(a.exclude), include=list(a.include),
        verify=a.verify, probe_ips=a.probe_ips, only_verified=a.only_verified,
        rules_files=list(a.rules), allowlist_file=a.allowlist, no_default_rules=a.no_default_rules,
        baseline_file=a.baseline, write_baseline_file=a.write_baseline,
        ai=a.ai, ai_model=a.ai_model, ai_url=a.ai_url,
        ai_gguf=a.ai_gguf, ai_max_calls=a.ai_max_calls,
        workers=a.workers, file_timeout=a.file_timeout, html_max=a.html_max, use_processes=not a.threads,
        show_per_type=a.show, min_sev=a.min_sev,
        no_color=a.no_color, context_width=a.context, mask=a.mask, autoinstall=a.autoinstall,
        smb_user=a.smb_user, smb_pass=a.smb_pass, smb_domain=a.smb_domain,
        smb_port=a.smb_port, smb_all=a.smb_all, s3_region=a.s3_region, s3_all=a.s3_all,
    )
    cfg.apply_profile(quick=a.quick, deep=a.deep)
    return cfg


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = args_to_config(args)
    Colors.auto(cfg.no_color)

    if not cfg.no_color:
        eprint(f"{Colors.CY}{_BANNER}{Colors.END}")

    eprint(f"{Colors.CY}Preparing dependencies...{Colors.END}")
    have = resolve(cfg.autoinstall, cfg.ocr, quiet=not sys.stderr.isatty())
    missing = [k for k, v in have.items() if not v]
    if missing:
        eprint(f"{Colors.Y}Optional extras unavailable:{Colors.END} {', '.join(sorted(missing))}")
    if cfg.verify:
        eprint(f"{Colors.Y}Live verification ON: discovered credentials will be tested against "
               f"provider APIs, and discovered IPs are probed to confirm they are real hosts. "
               f"Authorized audits only (--no-verify / --no-ip-probe to disable).{Colors.END}")

    scanner = Scanner(cfg)
    try:
        results = scanner.run()
    except (FileNotFoundError, RuntimeError) as exc:
        eprint(f"{Colors.R}Error: {exc}{Colors.END}")
        return 2
    except KeyboardInterrupt:
        eprint(f"\n{Colors.Y}Interrupted.{Colors.END}")
        return 130

    if not cfg.mask:
        eprint(f"{Colors.Y}Report shows REAL secret values (default). Use --mask for client-facing output.{Colors.END}")

    print_report(results, scanner.stats, cfg)
    for path in write_outputs(results, scanner.stats, cfg):
        label = path.rsplit(".", 1)[-1].upper()
        eprint(f"{Colors.G}{label}:{Colors.END} {path}")

    critical = sum(1 for r in results for f in r.findings if int(f.severity) >= 2 and not f.hidden)
    return 1 if critical else 0


if __name__ == "__main__":
    sys.exit(main())
