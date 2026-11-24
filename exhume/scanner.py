"""Scan engine: orchestrates sources, extractors, detectors and verification.

Built for multiprocessing: :func:`process_entry` is a module-level (picklable)
function each worker runs independently, loading custom rules from a per-process
cache.
"""
from __future__ import annotations

import concurrent.futures as cf
import os
import shutil
import tempfile
import time

from . import ai as ai_mod
from . import baseline
from .config import Config
from .console import Colors, eprint
from .detectors import aws_secret_candidates, cached_rules, scan_text
from .extractors import ExtractionBudget, extract, extract_document, ocr_image, read_textish, sqlite_peek
from .extractors.magic import (
    BINARY_SKIP,
    DOC_EXTRACT,
    IMAGE_EXT,
    classify,
    ext_of,
    sniff_magic,
)
from .models import FileResult, Finding, ScanStats, Severity, Verified, finding_sort_key
from .sources import docker as docker_src
from .sources import filesystem, git_history
from .sources import s3 as s3_src
from .sources import smb as smb_src
from .verify import VERIFIERS, verify_aws_pair, verify_single

_SQLITE_EXT = {".db", ".sqlite", ".sqlite3", ".db3", ".sqlitedb"}

# Worker config: set ONCE per process/thread (pool initializer), avoiding
# re-serializing Config on each of the thousands of tasks.
_WORKER_CFG: Config | None = None


def _init_worker(cfg: Config) -> None:
    global _WORKER_CFG
    _WORKER_CFG = cfg


def _scan_one(entry: tuple[str, str]) -> list[FileResult]:
    rp, dp = entry
    try:
        return [r for r in process_entry(rp, dp, _WORKER_CFG) if r.interesting]
    except Exception:
        return []


def _apply_path(findings: list[Finding], path: str) -> None:
    for f in findings:
        f.path = path


def _pair_aws(findings: list[Finding], fulltext: str) -> None:
    """Attach AWS secret-key candidates to each Access Key ID finding."""
    akias = [f for f in findings if f.detector == "AWS Access Key ID"]
    if not akias:
        return
    candidates = aws_secret_candidates(fulltext)
    for f in akias:
        if candidates:
            f.extra["aws"] = candidates
            f.detail = f.detail or "AWS secret pair present (use --verify to confirm)"


def process_entry(real_path: str, display_path: str, cfg: Config,
                  depth: int = 0, budget: ExtractionBudget | None = None) -> list[FileResult]:
    """Analyze one entry; may return several results (nested archives)."""
    try:
        size = os.path.getsize(real_path)
    except OSError:
        return []

    name = os.path.basename(display_path)
    ext = ext_of(name)
    magic_kind = sniff_magic(real_path)
    tags = classify(name, ext, magic_kind)
    rules_key = tuple(cfg.rules_files)
    extra_detectors, allow = cached_rules(rules_key, cfg.allowlist_file)

    rec = FileResult(path=display_path, name=name, ext=ext, size=size, tags=tags)

    if "database" in tags and (magic_kind == "database" or ext in _SQLITE_EXT):
        if cfg.db_peek and size <= cfg.max_bytes:
            rec.db_info = sqlite_peek(real_path)

    too_big = size > cfg.max_bytes

    # Archive -> extract and recurse
    is_archive = "archive" in tags
    if is_archive and depth < cfg.max_depth and not too_big and ext not in (".iso", ".img"):
        results = [rec]
        b = budget or ExtractionBudget(cfg.archive_max_mb * 1024 * 1024, cfg.archive_max_files)
        tmp = tempfile.mkdtemp(prefix="exhume_")
        try:
            if extract(real_path, ext, tmp, b):
                for child in filesystem.iter_dir(tmp, cfg.follow_links):
                    inner = f"{display_path} ::> {os.path.relpath(child, tmp)}"
                    results.extend(process_entry(child, inner, cfg, depth + 1, b))
                if b.exhausted:
                    rec.note = "extraction limit reached"
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return results

    # Executables and key material are string-scanned even without --strings, so
    # secrets embedded in binaries are still found; noisy media stays skipped.
    want_strings = cfg.scan_strings or "executable" in tags or "key_material" in tags

    # Choose the text-extraction method
    text: str | None = None
    method: str | None = None
    if ext in DOC_EXTRACT and not too_big:
        text, method = extract_document(real_path, ext)
    elif ext in IMAGE_EXT and cfg.ocr and not too_big:
        text, method = ocr_image(real_path)
    elif ext in BINARY_SKIP and not cfg.scan_strings:
        return [rec] if rec.interesting else []
    elif too_big:
        rec.note = f"skipped (>{cfg.max_size_mb}MB)"
        return [rec]
    else:
        text, method = read_textish(real_path, cfg.max_bytes, want_strings)

    if text is not None:
        rec.method = method
        findings = scan_text(text, cfg.min_entropy, allow, tuple(extra_detectors),
                             use_builtin=not cfg.no_default_rules, context_width=cfg.context_width)
        _apply_path(findings, display_path)
        _pair_aws(findings, text)
        rec.findings = findings
        if any("Private key" in f.detector for f in findings) and "key_material" not in rec.tags:
            rec.tags.append("key_material")
    else:
        rec.note = method

    return [rec] if rec.interesting else []


def scan_git_blob(blob: tuple[str, str, bytes], cfg: Config) -> FileResult | None:
    sha, rel, data = blob
    if data.count(0) / max(len(data), 1) > 0.02:
        return None
    text = data.decode("utf-8", "replace")
    rules_key = tuple(cfg.rules_files)
    extra_detectors, allow = cached_rules(rules_key, cfg.allowlist_file)
    findings = scan_text(text, cfg.min_entropy, allow, tuple(extra_detectors),
                         use_builtin=not cfg.no_default_rules, context_width=cfg.context_width)
    if not findings:
        return None
    path = f"git-history:{rel}@{sha[:12]}"
    _apply_path(findings, path)
    _pair_aws(findings, text)
    return FileResult(path=path, name=os.path.basename(rel), ext=ext_of(rel),
                      size=len(data), tags=["git_history"], findings=findings, method="git")


class Scanner:
    """Orchestrates a full scan of a target."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.stats = ScanStats()
        self._cleanup_dirs: list[str] = []

    # ----- target resolution -----
    def _resolve_target(self) -> tuple[list[tuple[str, str]], list, str]:
        cfg = self.cfg
        target = cfg.target
        entries: list[tuple[str, str]] = []
        git_blobs: list = []

        if smb_src.is_smb_target(target):
            eprint(f"{Colors.CY}SMB: downloading {target} ...{Colors.END}")
            tmp, prefix = smb_src.download(target, cfg)
            self._cleanup_dirs.append(tmp)
            entries = [(rp, f"{prefix}/{os.path.relpath(rp, tmp).replace(os.sep, '/')}")
                       for rp in filesystem.iter_dir(tmp, cfg.follow_links)]
            return entries, git_blobs, target

        if docker_src.is_docker_target(target):
            eprint(f"{Colors.CY}Docker: exporting image {target} ...{Colors.END}")
            tar_path, visual = docker_src.save_image(target)
            self._cleanup_dirs.append(os.path.dirname(tar_path))
            entries = [(tar_path, visual)]
            return entries, git_blobs, visual

        if s3_src.is_s3_target(target):
            eprint(f"{Colors.CY}S3: downloading objects from {target} ...{Colors.END}")
            tmp, visual = s3_src.download(target, cfg)
            self._cleanup_dirs.append(tmp)
            entries = [(rp, f"{visual}/{os.path.relpath(rp, tmp).replace(os.sep, '/')}")
                       for rp in filesystem.iter_dir(tmp, cfg.follow_links)]
            return entries, git_blobs, visual

        if os.path.isdir(target):
            root = os.path.abspath(target)
            entries = [(rp, rp) for rp in filesystem.iter_dir(
                root, cfg.follow_links, cfg.exclude, cfg.include)]
            if (git_history.is_git_repo(root) or cfg.force_git) and cfg.git_history:
                eprint(f"{Colors.CY}Git: reading full history...{Colors.END}")
                git_blobs = list(git_history.iter_git_blobs(root))
            return entries, git_blobs, root

        if os.path.isfile(target):
            ap = os.path.abspath(target)
            return [(ap, ap)], git_blobs, ap

        raise FileNotFoundError(f"'{target}' is not an accessible folder, file, repo or remote source.")

    # ----- execution -----
    def run(self) -> list[FileResult]:
        cfg = self.cfg
        t0 = time.time()
        results: list[FileResult] = []
        try:
            entries, git_blobs, display_root = self._resolve_target()
            self.stats.root = display_root
            self.stats.seen = len(entries)

            workers = cfg.resolved_workers()
            Executor = cf.ProcessPoolExecutor if cfg.use_processes else cf.ThreadPoolExecutor
            eprint(f"{Colors.CY}{len(entries)} entries + {len(git_blobs)} git blobs. "
                   f"{workers} workers ({'processes' if cfg.use_processes else 'threads'}), "
                   f"verify={'on' if cfg.verify else 'off'}.{Colors.END}")

            results.extend(self._scan_entries(entries, Executor, workers))
            results.extend(self._scan_git(git_blobs))

            if cfg.baseline_file:
                known = baseline.load_fingerprints(cfg.baseline_file)
                if known:
                    self.stats.suppressed = baseline.suppress_known(results, known)
                    eprint(f"{Colors.GR}Baseline: {self.stats.suppressed} known finding(s) hidden.{Colors.END}")

            if cfg.verify:
                self._verify(results)

        finally:
            for d in self._cleanup_dirs:
                shutil.rmtree(d, ignore_errors=True)

        self.stats.elapsed = time.time() - t0
        self.stats.scanned = sum(1 for r in results if r.method)
        self.stats.nested = sum(1 for r in results if " ::> " in r.path)
        self.stats.git_blobs = sum(1 for r in results if "git_history" in r.tags)
        self.stats.verified_live = sum(1 for r in results for f in r.findings
                                       if f.verified is Verified.LIVE)
        if cfg.ai and any(r.findings for r in results):
            res = ai_mod.triage(results, cfg.ai_url, cfg.ai_model)
            if res:
                self.stats.ai_summary = res["summary"]
                self.stats.ai_model = res["model"]
                eprint(f"{Colors.M}AI triage: {res['model']} summarized the findings.{Colors.END}")
        if cfg.write_baseline_file:
            n = baseline.write_fingerprints(cfg.write_baseline_file, results)
            eprint(f"{Colors.GR}Baseline written: {n} fingerprint(s) -> {cfg.write_baseline_file}{Colors.END}")
        return results

    def _scan_entries(self, entries, Executor, workers) -> list[FileResult]:
        out: list[FileResult] = []
        if not entries:
            return out
        total = len(entries)
        chunk = max(1, min(64, total // (workers * 4) or 1))
        try:
            with Executor(max_workers=workers, initializer=_init_worker, initargs=(self.cfg,)) as ex:
                for done, recs in enumerate(ex.map(_scan_one, entries, chunksize=chunk), 1):
                    out.extend(recs)
                    if done % 100 == 0 or done == total:
                        eprint(f"\r{Colors.GR}  {done}/{total}...{Colors.END}", end="")
        except Exception:
            # Sequential fallback if multiprocessing is unavailable in this environment.
            out.clear()
            eprint(f"\n{Colors.Y}Multiprocessing unavailable; running sequentially.{Colors.END}")
            _init_worker(self.cfg)
            for entry in entries:
                out.extend(_scan_one(entry))
        eprint("")
        return out

    def _scan_git(self, git_blobs) -> list[FileResult]:
        out: list[FileResult] = []
        for blob in git_blobs:
            try:
                rec = scan_git_blob(blob, self.cfg)
                if rec:
                    out.append(rec)
            except Exception:
                continue
        return out

    def _verify(self, results: list[FileResult]) -> None:
        cfg = self.cfg
        cache: dict = {}

        def verify_one(f: Finding) -> None:
            # AWS por par
            if f.detector == "AWS Access Key ID" and f.secret:
                for sk in f.extra.get("aws", []):
                    key = ("aws", f.secret, sk)
                    if key in cache:
                        status, detail = cache[key]
                    else:
                        status, detail = verify_aws_pair(f.secret, sk)
                        cache[key] = (status, detail)
                    if status is Verified.LIVE:
                        f.verified, f.detail, f.severity = status, detail, Severity.CRITICAL
                        return
                    if status is Verified.DEAD and f.verified is Verified.UNKNOWN:
                        f.verified, f.detail = status, detail
                return
            # Token de un solo valor
            if f.verifier in VERIFIERS and f.secret:
                key = (f.verifier, f.secret)
                if key in cache:
                    status, detail = cache[key]
                else:
                    status, detail = verify_single(f.verifier, f.secret)
                    cache[key] = (status, detail)
                f.verified, f.detail = status, detail
                if status is Verified.LIVE:
                    f.severity = Severity.CRITICAL

        jobs = [f for r in results for f in r.findings
                if (f.verifier in VERIFIERS or f.detector == "AWS Access Key ID")]
        if not jobs:
            return
        eprint(f"{Colors.CY}Verifying {len(jobs)} credential(s) against their APIs...{Colors.END}")
        with cf.ThreadPoolExecutor(max_workers=min(16, max(4, cfg.resolved_workers()))) as ex:
            list(ex.map(verify_one, jobs))


def sorted_findings(results: list[FileResult]) -> list[Finding]:
    all_f = [f for r in results for f in r.findings]
    return sorted(all_f, key=finding_sort_key)
