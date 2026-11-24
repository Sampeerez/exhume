# 🔎 Exhume

[![CI](https://github.com/your-org/exhume/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/exhume/actions/workflows/ci.yml)
[![Docker](https://github.com/your-org/exhume/actions/workflows/docker.yml/badge.svg)](https://github.com/your-org/exhume/actions/workflows/docker.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Sensitive-data discovery and verification suite for security audits and pentesting.**

*Verify + leak.* Exhume scans any target — folders, SMB shares (mounted or not), Docker images, S3 buckets, Git repositories or single files — and extracts **everything** that could be a secret: credentials, tokens, private keys, PII, **real** IP addresses and links (validated, not bare numbers), connection strings, databases and more. And it doesn't stop at finding them: it **confirms whether each credential is live** by authenticating against the provider API.

It doesn't only look where it's easy: it reads **inside** PDF, Word, Excel, PowerPoint, emails, images (OCR, on by default), nested archives, **executables and key files** (string-scanned), and the **full Git history**. It catches secrets even when the variable name isn't the usual one, thanks to a broad keyword set plus a high-entropy pass.

An optional **local-AI triage** (via Ollama, on by default when a model is present) prioritizes the findings — "which of these are the fastest paths to access" — right in the report. It only ever sees masked values and never leaves your machine.

When a match sits in a huge line (a minified JS file, a pasted dump), Exhume doesn't dump the whole wall of text at you — it shows a **focused window around the match** (configurable with `--context`), so you see only what matters.

> ⚠️ **For authorized audits only.** This tool — and especially `--verify`, which authenticates with the credentials it finds — must only be used against systems and data you have explicit written permission to test.

![Exhume demo](docs/demo.gif)

---

## ✨ Why Exhume

The leading tools are excellent but specialized:

| | Exhume | TruffleHog | Gitleaks | Nosey Parker |
|---|:---:|:---:|:---:|:---:|
| Regex + entropy | ✅ | ✅ | ✅ | ✅ |
| **Live credential verification** | ✅ | ✅ | ❌ | ❌ |
| Git history | ✅ | ✅ | ✅ | ✅ |
| **Inside PDF/DOCX/XLSX/PPTX** | ✅ | ⚠️ | ❌ | ❌ |
| **Image OCR** | ✅ | ❌ | ❌ | ❌ |
| **Nested archives (zip/tar/7z/rar)** | ✅ | ⚠️ | ❌ | ❌ |
| **Unmounted SMB** | ✅ | ❌ | ❌ | ❌ |
| Docker / S3 | ✅ | ✅ | ❌ | ❌ |
| **SQLite database peek** | ✅ | ❌ | ❌ | ❌ |
| **Validated IPs/URLs (real, not numbers)** | ✅ | ❌ | ❌ | ❌ |
| **Focused context around the match** | ✅ | ❌ | ❌ | ❌ |
| **Local-AI triage of findings** | ✅ | ❌ | ❌ | ❌ |
| Baseline / re-audit diffing | ✅ | ❌ | ✅ | ❌ |
| Custom rules | ✅ (YAML/JSON) | ✅ | ✅ (TOML) | ✅ |
| SARIF / JSON / CSV / HTML output | ✅ | ⚠️ | ✅ | ⚠️ |

Exhume combines TruffleHog's **verification**, the **Git history** scanning of Gitleaks/Nosey Parker, and adds what none of them do well: **reading inside office documents, images and nested archives**, which is where sensitive data actually hides in a real audit.

### Why Python and not Go/Rust?

The fastest tools for *raw regex* are written in Go (Gitleaks) or Rust (Nosey Parker). But Exhume's value isn't just scanning text fast — it's **extracting** content from PDF, DOCX, XLSX, PPTX, emails, OCR, SQLite and archives. Those extraction libraries live in the Python ecosystem and have no mature Go/Rust equivalent. Rewriting the engine would lose exactly what makes the tool unique.

Speed comes from engineering, not from switching languages:

- **True multiprocessing** (multi-core) — sidesteps the GIL for CPU-bound regex work.
- **Config is serialized once per worker**, not per task (big win on large trees).
- **Literal-anchor prefiltering** — a detector only runs its regex on lines containing its keyword.
- **Early skipping** of binaries and noisy directories; size caps.
- **Precompiled regex**, reused across all workers; **Git blob dedup** by SHA.

---

## 🚀 Installation

```bash
# Core (standard library only, works right away):
pip install -e .

# With all capabilities (documents, archives, SMB/S3, OCR, YAML):
pip install -e ".[full]"
```

Exhume **works with no optional dependencies** and **auto-installs** them the first time it needs one (disable with `--no-autoinstall`). OCR also needs the system `tesseract` binary.

### Docker

The image bundles everything (Python extras, `tesseract` for OCR, `git` for history scanning):

```bash
docker build -t exhume .
# Scan the current directory (mounted read-write at /scan):
docker run --rm -v "$PWD:/scan" exhume /scan --json
# Or pull the published image:
docker run --rm -v "$PWD:/scan" ghcr.io/your-org/exhume:latest /scan
```

### Pre-commit hook

Block commits that introduce secrets. In another repo's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/your-org/exhume
    rev: v7.0.0
    hooks:
      - id: exhume
```

Then `pre-commit install`. The hook runs an offline gate (`--no-verify --no-ai --no-html --min-sev high`) and fails the commit on High/Critical findings.

### CI/CD gate

Exhume exits with code **1** when any High/Critical finding is present, so it drops into a pipeline directly:

```yaml
# .github/workflows/secrets.yml
- run: pipx run exhume . --no-html --json -o exhume --min-sev high
```

---

## 📖 Usage

```bash
# Folder or mounted SMB share
exhume /mnt/share

# Full Git repo (history included) + verify live credentials, show only live ones
exhume . --git --verify --only-verified

# Unmounted SMB share
exhume smb://10.0.0.5/Finance --smb-user audit --smb-pass '***'

# Docker image
exhume docker://myapp:latest --sarif

# S3 bucket
exhume s3://my-bucket/logs --verify

# A single file (including an archive, which is opened recursively)
exhume backup.zip --strings --ocr

# Re-audit: only show what's NEW since last time
exhume . --baseline known.json --write-baseline known.json

# Reveal the real secret values (the operator needs them to use the credential)
exhume . --reveal
```

### Key options

| Option | What it does |
|---|---|
| `--no-verify` | Disable live verification (ON by default; makes network requests with found creds). |
| `--only-verified` | Show only **LIVE** credentials. |
| `--reveal` | Print the **real** secret values instead of masked ones (authorized use only). |
| `--git` / `--no-git-history` | Force / disable the Git-history scan. |
| `--baseline FILE` | Suppress findings already present in a baseline; `--write-baseline FILE` records the current ones. |
| `--exclude GLOB` / `--include GLOB` | Scope the scan by path glob (repeatable). |
| `--context N` | Context chars on each side of the match (def 64; `0` = value only). |
| `--strings` | Scan printable strings inside binaries/executables. |
| `--no-ocr` | Disable image OCR (on by default when tesseract is present). |
| `--rules FILE` | Custom YAML/JSON rules (repeatable). |
| `--allowlist FILE` | Regexes (one per line) to ignore. |
| `--no-ai` / `--ai-model` | Disable / choose the local-AI triage model (Ollama). |
| `--deep` / `--quick` | Exhaustive / fast profiles. |
| `--json --csv --sarif` | Extra output formats (HTML always, unless `--no-html`). |

Run `exhume --help` for the full list.

### Credential verification

Verification is **on by default** (disable with `--no-verify`). Inspired by TruffleHog: for detectors with a verifier, Exhume makes **one** request to the provider API and classifies each finding as:

- **✓ LIVE** — the credential authenticates (real access).
- **✗ dead** — rejected (401/403).
- *unknown* — no network or no verifier.

Providers with active verification: **AWS** (SigV4 signature against STS `GetCallerIdentity`, pairing Access Key + Secret), GitHub, GitLab, Slack, Stripe, SendGrid, DigitalOcean, Telegram, Discord, npm and Postman.

### Local AI triage

With [Ollama](https://ollama.com) running locally, Exhume sends the (masked) findings to your local model and gets back a prioritized, pentester-oriented summary — an executive overview, the fastest paths to access, and recommended next steps — rendered at the top of the HTML report and in the console. It is **on by default** and **silently skipped** when no local model is reachable. Detection and verification never depend on the AI: they are deterministic. Nothing is sent to any cloud, and the model only ever receives masked values.

```bash
exhume . --verify                 # AI triage runs automatically if Ollama is up
exhume . --ai-model qwen2.5:7b    # pick a model
exhume . --no-ai                  # disable triage
```

---

## 📊 The report

Every scan writes a self-contained **HTML dashboard** with summary cards (Critical / High / Medium / Verified-live / Total), a severity bar, live filtering by text and severity, and a "verified only" toggle. JSON, CSV and SARIF are available too (`--json --csv --sarif`) for pipelines and tools like GitHub code scanning or DefectDojo.

---

## 🧩 Architecture

Modular package, each piece with a single responsibility:

```
exhume/
├── cli.py              # command-line interface
├── config.py           # configuration (picklable dataclass)
├── models.py           # Finding, FileResult, Severity, Verified
├── scanner.py          # engine: orchestrates everything (multiprocessing)
├── baseline.py         # re-audit diffing (fingerprints)
├── ai.py               # optional local-AI triage (Ollama)
├── deps.py             # optional dependencies + auto-install
├── detectors/          # detection engine
│   ├── patterns.py     #   ~68 built-in detectors
│   ├── entropy.py      #   Shannon + Luhn
│   ├── validators.py   #   real IP/URL/card validation (ipaddress)
│   └── rules.py        #   YAML/JSON rules + allowlist
├── extractors/         # content extraction
│   ├── documents.py    #   PDF, DOCX, XLSX, PPTX, EML, MSG
│   ├── archives.py     #   zip/tar/gz/7z/rar (recursive, zip-bomb safe)
│   ├── text.py         #   binary-aware reading + strings
│   ├── ocr.py          #   image OCR
│   ├── sqlite_peek.py  #   database inspection
│   └── magic.py        #   extension + magic-byte classification
├── sources/            # where to read from
│   ├── filesystem.py · git_history.py · smb.py · docker.py · s3.py
├── verify/             # active credential verification
└── reporting/          # console · html · json · csv · sarif
```

---

## 🔒 Report safety

Reports get shared, so a secret's **plaintext value is never written** to output by default: both the value and the context line are masked (even with several credentials on the same line). The secret only lives in memory during the run. Pass `--reveal` to include real values when the operator needs them — the output is then clearly flagged as confidential. The bundled `.gitignore` keeps reports and evidence out of the repo.

---

## 🧪 Development

```bash
make install-full   # install with extras + dev tools
make test           # pytest
make cov            # coverage
make lint           # ruff
```

The suite covers detectors, entropy/Luhn, validators, nested archives, Git history, rules, verification (HTTP mocked), reporting, baseline/exclude and end-to-end integration.

---

## ⚖️ Legal notice

Exhume is a tool for **security professionals performing authorized audits**. Using `--verify` authenticates against real services with the discovered credentials. You are solely responsible for having explicit written authorization over the systems and data you analyze. The authors are not liable for misuse.

## 📄 License

MIT — see [LICENSE](LICENSE).
