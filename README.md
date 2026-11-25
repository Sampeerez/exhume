<div align="center">

# 🔎 Exhume

**Unearth buried secrets — and know which ones are real.**

Sensitive-data discovery and verification for security audits and pentests.

[![CI](https://github.com/Sampeerez/exhume/actions/workflows/ci.yml/badge.svg)](https://github.com/Sampeerez/exhume/actions/workflows/ci.yml)
[![Docker](https://github.com/Sampeerez/exhume/actions/workflows/docker.yml/badge.svg)](https://github.com/Sampeerez/exhume/actions/workflows/docker.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)
![Local AI](https://img.shields.io/badge/AI-100%25%20local-8b5cf6)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

![Exhume demo](docs/demo.gif)

</div>

> ⚠️ **Authorized audits only.** Exhume authenticates with the credentials it finds and probes the IPs it
> discovers. Use it only on systems and data you have written permission to test.

## What it does

Point it at a folder, an SMB share, a Docker image, an S3 bucket, a Git repo (history included) or a single
file. Exhume reads **inside** PDF, Word, Excel, PowerPoint, e-mails, images (OCR), nested archives,
binaries and **databases** — every row/column is read, not just column names, for SQLite, dBase (`.dbf`)
and MongoDB dumps (`.bson`) directly, and for Access (`.mdb`/`.accdb`) when `mdbtools` is installed; a
BLOB/binary cell that looks like an embedded file is extracted and scanned too. Proprietary engines with
no portable single-file format (MySQL's own storage files, SQL Server, Oracle, Redis dumps...) are at
least string-scanned instead of skipped — see [Database support](#database-support) for the full table.
It reports credentials, tokens,
private keys, PII (cards, IBAN, DNI/NIE, SSN), IPs, URLs and connection strings. Then it works out
**which findings are real**, and reports the same value **once** no matter how many files it's in:

| Step | What happens |
|---|---|
| **1 · Detect** | ~70 detectors + a high-entropy pass, with a focused snippet around each match. The same value found in many places is one finding with an occurrence count, not one row per occurrence. |
| **2 · Check** | IBAN (mod-97 + Spanish account digits), cards (Luhn), DNI/NIE (control letter); every IP is probed (TCP + reverse DNS). Nothing is dropped — failures are flagged *invalid*. |
| **3 · Verify** | Credentials are tested against the provider API (AWS, GitHub, GitLab, Slack, Stripe…) → **LIVE** / dead. |
| **4 · Judge & brief** | A **bundled local AI** reads each ambiguous match in context: `3.2.2.1` in a manual is not an IP, an invoice total is not a card. It also writes a one-line risk note for sensitive databases and a short triage summary, so the auditor gets a head start, not just a list. |

## Quick start

Install it once as a global command with [pipx](https://pipx.pypa.io) — no venv to activate, `exhume` just
works from any directory, in any terminal, from then on:

```bash
pipx install "git+https://github.com/Sampeerez/exhume"

exhume /path/to/target        # that's it: scan → HTML report opens in your browser
```

(No `pipx`? `pip install pipx` first, or `brew install pipx`. If the shell can't find `exhume` right
after installing, run `pipx ensurepath` once and open a new terminal — that puts pipx's bin folder on `PATH`.)

No `[full]`, no extra flags: every optional piece (PDF/Office readers, archive formats, OCR, SMB/S3,
MongoDB dumps, and the local AI runtime) **installs itself the first time it's actually needed** —
including inside the isolated environment pipx creates, where plain `pip` isn't normally available
(Exhume re-bootstraps it on its own via the standard library's `ensurepip`). Exhume writes
`exhume_report.html` (interactive) and `exhume_report.csv` (every finding) next to where you run it.

**First run:** the local AI installs itself too — `llama-cpp-python` plus a 2.1 GB open model
(Qwen2.5-3B) cached in `~/.cache/exhume`, shared by every install method and reused across runs
(verdicts are remembered too). Prefer to skip it? `--no-ai`.

**Data privacy, enforced, not just promised:** your scanned data is for the auditor's eyes only —
the output files (HTML/CSV/JSON/SARIF) are written locally and Exhume never uploads them anywhere.
The bundled AI runs in-process on your machine (no socket involved at all); the only thing that ever
touches the network for it is the one-time model download from Hugging Face, before any scanning
happens. If that bundled model can't run and Exhume falls back to Ollama, `--ai-url` is checked
against the loopback interface (127.0.0.1/::1/"localhost") **before any data is sent** — a URL that
resolves anywhere else is refused outright, not silently used, so pointing it at a remote host
disables the AI rather than leaking findings to it. See [`exhume/ai.py`](exhume/ai.py)'s
`is_local_url` for the exact check, and [`tests/test_ai.py`](tests/test_ai.py) for the tests that
pin this behavior down.

<details>
<summary>Requirements & other ways to install</summary>

- Python 3.9+, macOS or Linux. OCR needs the `tesseract` binary (`brew install tesseract` / `apt install tesseract-ocr`);
  reading Access databases needs `mdbtools` (`brew install mdbtools` / `apt install mdbtools`) — both optional.
- The AI runtime ships as a prebuilt wheel for common platforms; otherwise it needs a C/C++ toolchain + CMake. If it can't
  be installed, Exhume falls back to a running [Ollama](https://ollama.com) or just reports matches unjudged.
- **From a clone, for development** (editable, so code changes apply immediately):
  ```bash
  git clone https://github.com/Sampeerez/exhume && cd exhume
  python3 -m venv .venv && source .venv/bin/activate
  pip install -e .          # core only — extras still auto-install as needed
  # or: pip install -e ".[full]"   to pre-install every extra up front (CI, offline use, etc.)
  ```
  `--no-autoinstall` turns off the self-install behavior entirely, for either method above.
- **Docker** (everything bundled, `mdbtools` included; keep the model between runs with a volume):
  ```bash
  docker build -t exhume .
  docker run --rm -v exhume-cache:/home/auditor/.cache/exhume -v "$PWD:/scan" exhume /scan --no-open
  ```
</details>

## Usage

```bash
exhume /mnt/share                                  # folder or mounted share
exhume . --git --only-verified                     # repo + full history, show only LIVE credentials
exhume smb://10.0.0.5/Finance --smb-user audit --smb-pass '***'
exhume docker://myapp:latest --sarif               # image
exhume s3://my-bucket/logs                         # bucket
exhume backup.zip --deep                           # archive, exhaustive (strings + OCR + depth)
exhume . --baseline known.json --write-baseline known.json   # re-audit: only what's new
exhume . --mask --no-open                          # client-safe output
```

<details>
<summary>All the options that matter</summary>

| Option | Effect |
|---|---|
| `--no-ai` · `--ai-gguf FILE` · `--ai-max-calls N` | Disable the AI · use another `.gguf` model · cap model calls (default 4000) |
| `--no-verify` · `--no-ip-probe` | No credential API calls · no IP probing (offline gate) |
| `--only-verified` | Show only LIVE credentials |
| `--mask` | Mask secret values (default shows real ones — the operator needs them) |
| `--no-open` · `--no-csv` · `--no-html` · `--json` · `--sarif` | Choose outputs (HTML + CSV by default) |
| `--html-max N` | Findings embedded in the HTML, highest severity first (default 50 000; the CSV always has all) |
| `--git` / `--no-git-history` | Force / skip Git history |
| `--include` / `--exclude GLOB` | Scope by path (repeatable) |
| `--strings` · `--no-ocr` · `--quick` · `--deep` | Binary strings · OCR off · fast / exhaustive profiles |
| `--rules FILE` · `--allowlist FILE` | Custom YAML/JSON rules ([example](rules/example.yaml)) · regexes to ignore |
| `--file-timeout S` · `--workers N` | Per-file time limit (default 120 s) · parallelism |
| `--no-db-peek` · `--db-max-rows N` | Don't open databases at all · rows sampled per table when scanning their content (default 5000) |

`exhume --help` lists everything. Exit code is `1` when High/Critical findings exist.
</details>

## The report

An interactive, self-contained HTML dashboard:

- **One row per value** — a password or e-mail pasted into 30 files shows up once, with a `×30` badge and
  every location (expand the row, or check the `occurrences`/`locations` columns in the CSV/JSON).
- **Filter & triage** — by severity, detector or text; paginated, so it stays fast with 100 000+ findings.
- **Real vs. noise** — "Hide invalid / AI false positives" is on by default (one click to see what was discarded and *why*).
- **Dismiss** false positives yourself — one value, or a whole detector; saved in your browser; **Export reviewed CSV**.
- **📷 Report mode** — censors values and context, shows relative paths and hides every control, ready for a client screenshot.
- **Assets** — databases, configs, keys and executables as collapsible folder trees (thumbnail caches and similar noise filtered out), with a one-line **AI risk summary** next to each sensitive database.
- **Coverage** line: how many files were scanned, skipped or unreadable — so you know nothing was silently missed.

## Database support

| Engine | What Exhume does |
|---|---|
| **SQLite** (any extension — detected by content) | Full: every row/column, embedded files inside BLOBs scanned recursively. |
| **dBase / xBase** (`.dbf`) | Full: every row/column. Built in, no extra install. |
| **MongoDB dumps** (`.bson`, from `mongodump`) | Full: every document, including nested fields; large binary fields scanned recursively. Needs `pymongo` (auto-installed). |
| **MS Access** (`.mdb`, `.accdb`) | Full, when [`mdbtools`](https://github.com/mdbtools/mdbtools) is on `PATH` (`brew install mdbtools` / `apt install mdbtools`; bundled in the Docker image). Falls back to string-scanning otherwise. |
| **Plain-text SQL dumps** (`.sql`, `.dump`, `.bak` that are actually text) | Scanned as text, like any other file — nothing special needed. |
| **MySQL's own files** (`.frm`/`.myd`/`.ibd`), **SQL Server** (`.mdf`/`.ldf`/`.ndf`), **Redis** (`.rdb`) | String-scanned (catches plaintext secrets; misses binary-packed/compressed data). These are a running server's internal storage, not a portable single-file format — there's no safe, reliable way to parse them offline. |
| **Oracle, DB2, Firebird** and other proprietary engines | Not specifically supported; treated as an ordinary binary file. |

`--no-db-peek` skips all of the above; `--db-max-rows` (default 5000) caps rows sampled per table.

## Use it in your pipeline

```yaml
# .pre-commit-config.yaml — blocks commits that add High/Critical secrets (offline, no AI)
repos:
  - repo: https://github.com/Sampeerez/exhume
    rev: main
    hooks:
      - id: exhume
```

```yaml
# GitHub Actions — fails the job on High/Critical findings
- run: pipx run --spec "git+https://github.com/Sampeerez/exhume" exhume . --no-open --no-csv --no-ai --no-verify --min-sev high
```

## Under the hood

```
exhume/
├── scanner.py      engine (multiprocessing, per-file timeout, coverage counters)
├── detectors/      patterns · entropy · validators (IBAN/card/DNI/IP) · custom rules
├── extractors/     documents · archives · OCR · databases (SQLite/DBF/BSON/Access) · magic bytes
├── sources/        filesystem · git history · SMB · Docker · S3
├── verify/         credential verifiers (provider APIs) · IP liveness
├── ai_filter.py    bundled local AI: judges matches & assets, verdict cache
├── ai.py           triage summary (bundled model, or Ollama)
└── reporting/      console · html · json · csv · sarif
```

Python rather than Go/Rust on purpose: the value is *extracting* content from office files, images and archives,
where the best libraries live. Speed comes from true multiprocessing, anchor-based regex prefiltering, early
skipping of binaries and Git-blob dedup.

## Development

```bash
make install-full   # extras + dev tools        make test   # pytest
make lint           # ruff                      make demo   # regenerate docs/demo.gif from a real run
```

## Legal

Exhume is for **security professionals performing authorized audits**. You are solely responsible for having
explicit written authorization over the systems and data you analyze; the authors accept no liability for misuse.

MIT licensed — see [LICENSE](LICENSE).
