# Changelog

All notable versions of Exhume.

## [Unreleased]

### Added
- `--file-timeout` (default 120 s): a file that takes too long is skipped and reported
  as `skipped (timeout >Ns)` instead of stalling the whole scan.

- `--html-max` (default 50000): the HTML report embeds the highest-severity findings up to this
  limit and, when truncated, an extra `.csv` with every finding is written automatically.

- HTML report: **Report mode** (📷) censors values and surrounding context, shows relative paths and
  hides controls for client-safe screenshots; findings can be dismissed as false positives
  (per finding, per file/value/detector, or all filtered), persisted in the browser, excluded in
  report mode, with "Export reviewed CSV".
- HTML report: assets (executables, archives, …) are collapsible folder trees instead of long lists.
- Coverage summary (content scanned / media skipped / unreadable / too big …) in console, JSON and HTML.

- **Bundled local AI that judges matches in context** (`exhume/ai_filter.py`): installs
  `llama-cpp-python` and downloads Qwen2.5-3B-Instruct (Q4, ~2.1 GB, cached in `~/.cache/exhume`) on
  first run, so nothing has to be pre-installed (Ollama is a fallback). Ambiguous matches (IPs, cards,
  IBANs, DNI/NIE/SSN, password assignments) are judged REAL or FALSE from their surrounding text; false
  positives are kept but hidden by default. Calls are deduplicated and inherited within homogeneous
  (file, detector) groups; capped by `--ai-max-calls`. `--ai-gguf` uses another model; `--no-ai` disables. Verdicts use token
  probabilities with few-shot examples (a match is hidden only when the model is confident), and only
  the match's own line is shown to the model.
- The AI also drops noise **assets** (database/config listings such as caches or resource files);
  assets holding findings or sensitive columns are never hidden. Housekeeping files (`Thumbs.db`,
  `.DS_Store`, `desktop.ini`, `~$*`, ...) are excluded without AI.

### Changed
- Fewer false positives in credential detection: placeholders like `[Password]` and binary garbage
  decoded as text are dropped.
- Sensible defaults, no flags needed: the HTML report opens automatically and a CSV with every
  finding is always written (opt out with `--no-open` / `--no-csv`).
- HTML report is paginated (100 rows/page), builds row details lazily and loads data in chunks.

- **Nothing is dropped for being "unreal": it is checked instead.** IBAN (mod-97, country length and
  Spanish account control digits), credit cards (Luhn, dummy-number detection), DNI/NIF and NIE
  (control letter) are kept and flagged VALID / INVALID. Every discovered IP is checked against the
  network (TCP probe on common ports + reverse DNS, deduplicated) and flagged VALID (host answers /
  has PTR) or INVALID (no response). Disable the network check with `--no-ip-probe`.
- HTML report: invalid matches are hidden by default behind a "Hide invalid" toggle (with a counter)
  and excluded from the cards; console shows only a count. CSV/JSON keep them all.

### Fixed
- HTML report rendered blank on very large scans (hundreds of thousands of findings / ~850 MB).
- CI: pin the runner to `ubuntu-24.04`; `ubuntu-latest` (26.04) no longer ships Python 3.9.
- Scan hanging near the end on pathological PDF/XLSX files.
- Noisy openpyxl warnings and pdfminer messages are now suppressed in workers.

## [7.0.1] — 2026-11-24

### Fixed
- Test fixtures used realistic sample tokens that tripped GitHub Push Protection
  (and other scanners) on `git push`. The sample values are now split in source
  (`"glpat-" + "..."`) so the full provider-format literal never appears in a file,
  while still being reassembled at runtime so detection tests keep passing.

## [7.0.0] — 2026-11-24

### Changed
- Renamed to **Exhume** (unearth buried secrets, including from Git history). Command: `exhume`.
  Removed the emoji from the banner and the HTML brand for a cleaner look.
- **Live verification is now ON by default** (disable with `--no-verify`). Credentials that
  cannot be verified are still reported so they can be tested manually.

### Added
- **Pre-commit hook** (`.pre-commit-hooks.yaml` + example `.pre-commit-config.yaml`): an
  offline gate that blocks commits on High/Critical findings.
- **Animated demo** at `docs/demo.gif`, shown in the README.

### Changed (report)
- Triage summary card restyled with a clean header, uppercase section labels and dotted
  list markers (no emoji, no gradient).

## [6.1.0] — 2026-11-24

### Added
- **Dockerfile** (bundles tesseract for OCR and git for history scanning) and a
  `.dockerignore`; run with `docker run --rm -v "$PWD:/scan" exhume /scan`.
- **GitHub Actions**: CI (lint + tests on Python 3.9/3.11/3.13, with pip cache) and a
  Docker workflow that builds on every push/PR and publishes to GHCR on version tags.
- README badges and a CI/CD gate example.

### Changed
- **Triage summary** card restyled: cleaner header with a subtle "prioritization" tag,
  uppercase section labels and dotted list markers — no emoji, no gradient.
- HTML: click a value to copy it, `/` focuses the filter, `Esc` clears it, location
  now shows line:column.

## [6.0.0] — 2026-11-24

### Changed
- Renamed to **Exhume** (verify + leak) — a unique, concrete name for the
  "finds leaks and proves they're live" workflow. Command: `exhume`.

### Added
- **Local AI triage (Ollama), on by default.** When a local model is reachable it
  prioritizes the findings ("fastest paths to access") and the result is shown in the
  HTML report and console. It receives only MASKED values, never plaintext, and never
  leaves the machine (local, proxy-bypassed). Silently skipped if no model is present.
  Flags: `--no-ai`, `--ai-model`, `--ai-url`.
- **"Copy live creds"** button in the HTML report.

### Improved coverage
- **OCR of images is on by default** (auto-skips when tesseract is absent).
- **Executables and key-material files are string-scanned by default**, so secrets
  embedded in binaries are found (noisy media still skipped unless `--strings`).
- **Broader credential keywords** (passphrase, bearer, access/refresh token, secret_key,
  private_key, credential, dsn, connection string, ...) so non-default variable names
  are caught; the high-entropy pass still catches oddly-named assignments.

## [5.1.0] — 2026-11-24

### Changed
- **Reports now show REAL secret values by default** (the report is for the pentester).
  Use `--mask` for a client-facing report; masking is applied at report time.

### Added
- **Interactive HTML report**: expandable rows with highlighted multi-line context
  (the exact surrounding code/lines, with the match marked), per-finding copy buttons
  (value & path), clickable summary cards, detector filter, search and verified-only toggle.
- Each finding now records its **column** and a **multi-line context block**.

### Improved
- **Far fewer false positives**: credential detectors reject code references
  (`password = req.body.password`), function calls, type annotations and templates,
  while now catching prefixed env vars like `DB_PASSWORD=` / `MYSQL_PASSWORD=`.

## [5.0.0] — 2026-11-24

Renamed to **Exhume** 🐾 and switched the whole project to English for a wider
international audience, plus new pentest-focused features and a redesigned report.

### Added
- **`--reveal`**: print the real secret values (not just masked ones) for the
  operator who needs the credential to gain access. Clearly flagged as confidential.
- **Baseline diffing** for re-audits: `--baseline FILE` suppresses already-known
  findings, `--write-baseline FILE` records the current fingerprints.
- **Path scoping**: `--exclude GLOB` / `--include GLOB` (repeatable).
- **Redesigned HTML dashboard**: summary cards, severity bar, live filtering by
  text/severity and a "verified only" toggle.
- **US SSN** detector.

### Changed
- Renamed package and command: `sabueso` → **`exhume`**.
- Entire codebase, comments, detector names, asset tags, output, report keys and
  docs translated to **English**.
- JSON report keys are now English (`summary`, `findings`, `assets`, ...).

## [4.1.0] — 2026-11-24 (as Sabueso)

### Added
- Real network-data validation (IPv4 private/public, IPv6, URLs) via `ipaddress`.
- Focused context window around each match (`--context`).
- Dedupe of overlapping findings.

### Changed
- `Config` sent once per worker (pool initializer) for faster large scans.

## [4.0.0] — 2026-11-24

Full rewrite as a modular package with tests, packaging and new sources
(Docker, S3). Live verification (AWS SigV4, GitHub, Slack, Stripe, ...),
Git history, office documents, OCR, nested archives, SMB, SQLite peek.
Plaintext secrets are never serialized to reports.
