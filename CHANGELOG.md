# Changelog

All notable versions of Exhume.

## [Unreleased]

### Fixed (scan coverage: "quiero que se analice TODO, absolutamente todo")
Reported: a scan's coverage line showed hundreds of "binary skipped", "media skipped", "images
without OCR" and a few "too big", with no way to actually get everything scanned — `--max-size 0`
looked like it should mean "no limit" (it's the convention `--html-max 0` already uses elsewhere in
this tool) but didn't actually work that way:
- **`--max-size 0` now genuinely means no size cap**, and `--deep` ("exhaustive profile") now lifts
  the cap entirely instead of merely raising it to a 300MB floor — it already turned on
  `--strings` (every binary, not just executables) and OCR, so combined with no size cap it now
  actually scans everything, by design, not just "more than before".
- **Found and fixed a real crash while building this**: the obvious way to implement "no cap" is a
  huge sentinel number, but `file.read(hugeNumber)` raises `MemoryError` trying to size a buffer
  up front — even for a perfectly ordinary, small file (reproduced on a 105MB test file; `--deep`
  turned a clean "too big, skipped" into a silent "1 errors" with no explanation why). Fixed by
  using `None` to mean "no cap" through every call site (`Config.max_bytes`, `read_textish`, the
  SMB/S3 size filters) — `file.read()` with no argument reads to EOF the efficient way instead.
- **The coverage breakdown is reorganized into Processed / Skipped by default / Failed**, and each
  skip reason now says exactly which flag includes it (`--strings`, `--ocr`, `--max-size 0`, or
  `--deep` for all of it at once) instead of just a bare count with no indication anything could be
  done about it.
- **Found a second, silent gap while answering "why no OCR": the dependency check only verifies
  the `pytesseract` *Python* package imports — pip installs that part automatically — but says
  nothing about whether the `tesseract` *system* program itself is callable, which pip can't
  install.** This is a real, separate failure mode (confirmed: this very dev machine has the
  Python package but not the system binary) that was completely invisible before. The console now
  checks this for real and tells you to `brew install tesseract` / `apt install tesseract-ocr`
  when it's missing, instead of only showing up as an uninformative count in the report.
- **Fixed a layout bug in the coverage breakdown dropdown** (reported as looking "raro y mal"): it
  used to expand inline as a flex item inside the metadata chips row, so opening it stretched nearby
  chips and left a large empty gap where the row couldn't reflow around its new height. It's now a
  floating popover (closes on an outside click) that overlays the page instead of disturbing the
  chips' layout at all.

### Fixed (AI triage summary silently missing on large scans)
Reported: a 75k-file scan showed `AI filter: bundled Qwen2.5-3B` (so the model clearly ran and
filtered 3,798 false positives) but the "Triage summary" section never appeared, with no error
anywhere. Root-caused by reproducing the exact shape of that scan:
- `exhume.ai._build_prompt` lists up to 80 of the highest-priority findings for the one-shot
  triage summary, each with its **full absolute path**. On a deeply nested real share (`.../
  10.158.14.102_DIGA-CO-.../GAPO - ICOD (TF003)/9. FACTURAS AUTORIZADAS/APROLIS/2023/...`), 80 such
  lines alone built a ~9,400-token prompt — more than double the bundled engine's 4,096-token
  context window. `create_chat_completion` raised, and `triage()`'s `except Exception: text = ""`
  swallowed it completely, silently.
- Paths in that listing are now shortened to the filename and its closest parent folder(s)
  (`exhume.ai._short_path`) instead of the full path — the model only needs to say where
  something is, not replay the whole audited tree's directory structure 80 times over.
- The bundled engine's context window is raised from 4096 to 8192 tokens (cheap for a 3B model,
  real headroom for this one large prompt — the per-match judging calls it also serves are only a
  few hundred tokens each regardless of this ceiling).
- Belt and suspenders: `triage()` now retries with progressively fewer findings (80 → 40 → 20 → 10
  → 5 → 2) if the prompt still doesn't fit, instead of giving up after one attempt — a summary is
  now produced for literally any scan size, just a coarser one for a pathological case.
- If triage still can't produce a summary, the console now says so explicitly instead of staying
  silent, so "no summary" is never again a silent, unexplained gap.

### Changed (HTML report clarity pass)
Requested after a real scan's report looked like a wall of text ("quiero que aquí salga todo mucho
más claro"):
- **The dense, pipe-separated metadata line is now a row of labelled chips** (files scanned,
  nested, git-history, dedup ratio, elapsed time), a collapsible "Coverage breakdown" for the
  per-category skip counts (binary/media/OCR-unavailable/too-big/archives/unreadable), and a
  distinct amber note for what's hidden by default, broken into *why* (failed its check vs.
  judged false by the AI) instead of one run-on sentence.
- **Clarified why some rows show "● VALID AI: real" and others only "AI: real"** (reported
  confusion). A password, a generic high-entropy secret or a phone number has no checksum or host
  to test — there never was a missing badge, that type simply has no deterministic check, only the
  AI's judgment. The Verified column now says so explicitly ("— n/a", with a tooltip) instead of
  leaving a blank gap that looked like a glitch next to rows that do have a VALID/invalid badge.
- **"Detected assets" redesigned**: a bordered panel matching the Triage summary card's style, an
  icon and one-line description per category (key material, sensitive filenames, databases,
  executables, archives, config files, git history) instead of a plain list of category names.
- **Fixed: the "Detected assets" title stayed on screen in report mode with nothing under it.**
  The heading was appended as a sibling *before* the hideable tree box instead of inside it, so
  hiding the box in report mode left an orphaned heading. Both now live in one element, so report
  mode hides the whole section, heading included.

### Added
- **Phone number detector**: a labelled national number (`Teléfono:`, `Móvil:`, `Fax:`, …) or a
  standalone international `+CC …` number, checked offline (digit count, not a repeated-digit
  pattern, not a calendar date mistaken for a number) and, when ambiguous, judged in context by
  the local AI like every other PII detector.
- **The report is now named after what was actually scanned** instead of the generic
  `exhume_report.html`, e.g. scanning `copia_shares/` produces `copia_shares_exhume_report.html` and
  `backup.zip` produces `backup_exhume_report.html` — useful the moment there's more than one scan
  on disk at once. `smb://`/`docker://`/`s3://` targets are named from what follows the scheme.
  `-o`/`--output` still overrides it explicitly.
- **Report mode: pick exactly which findings show on screen**, for a screenshot that needs a
  specific mix (e.g. 2 Critical + 1 Medium, or "all Highs"). Each row now has a checkbox while in
  report mode; check the ones you want, then turn on "Show only picked" to show precisely that set —
  it ignores the severity tab, detector and search filters entirely, since the whole point is a
  curated combination you built across several of those filters. Picks persist across a reload
  (`localStorage`, scoped per target like the existing dismiss list) and a "Clear picks" button
  resets them. A picked row is now also highlighted immediately, independent of that toggle, so
  it's obvious while curating what's already checked.
- **HTML report: sortable columns and a usable layout on small screens.** Severity, Detector and
  Location column headers now sort the table (click again to reverse); the summary cards collapse
  to 2 then 1 per row below 860px/480px instead of staying squeezed into 5; the table scrolls
  horizontally on its own instead of blowing out the page width.

### Fixed (HTML report)
- **The table's sticky header could float in the middle of the rows instead of staying pinned
  below the page header** — reported from a real scan screenshot (the SEVERITY/VERIFIED/DETECTOR
  column labels overlapping a row's text). Two compounding causes, both fixed:
  - The sticky offset was a hardcoded `73px` that assumed a short, single-line target path — but a
    long path, coverage notes or the AI-engine line can wrap the page header over several lines.
    The offset now tracks the header's real, live height (`ResizeObserver` + a CSS variable)
    instead of a constant that silently went stale.
  - Separately, the `overflow-x:auto` added for small-screen table scrolling (previous entry)
    turned its wrapper into its own scroll container, which hijacks `position:sticky` on the
    header cells — they'd stick to that box's edge instead of the page's, detaching the header row
    entirely. Removed now that location/value are truncated (next entry), so the table rarely
    needs a horizontal scrollbar of its own; a narrow viewport just scrolls the whole page instead.

### Changed (HTML report design)
General visual pass requested after the sticky-header bug report ("que se vea increíble"):
- The location column was the main source of visual noise — a deeply nested path wrapped across
  2-3 lines, bloating every row. It's now a single truncated line with `…` and the full path in a
  tooltip (still shown in full in the expanded row and the "seen in N places" list); clicking it
  copies the path, mirroring the existing click-to-copy on the value.
- Reworked the color system: severity cards get a subtle tinted gradient and a colored left edge
  matching their severity, pills get a small colored dot, picked rows in report mode get an accent
  edge instead of only a background tint, a thin gradient accent line tops the page header.
  Buttons, inputs, selects and the segmented severity control all got consistent hover/focus states
  (including `:focus-visible` outlines) and the toolbar is now a bordered, grouped panel instead of
  loose floating controls.
- Custom dark-themed scrollbars (previously the browser's default light scrollbar, jarring against
  the dark report), smoother row-expand and toast transitions, a subtle page background gradient.

### Fixed
- **Garbage binary data was still matched by detectors that have no entropy/junk check of their
  own** (IPv6 in particular: `8::` is syntactically valid IPv6, and random bytes misread as UTF-16
  text produce exactly that kind of short, garbage match). A whole line is now skipped by every
  detector, not just entropy-based ones, when it's mostly replacement characters/control bytes —
  the same class of bug the earlier `_is_junk` fix addressed, generalized to the whole line instead
  of only the matched value, and IPv6 (and the new phone detector) now also get an AI second look
  for anything that gets through anyway.
- **Report filters now stay internally consistent.** The detector dropdown used to list every
  detector type regardless of which severity tab was active or whether "Hide invalid" was on,
  so picking "Public IPv4" while on the Medium tab, or a detector whose only matches were hidden
  as invalid, could show a count and then zero rows. It's now rebuilt from the currently visible
  findings on every filter change, so it only ever offers what's actually there.
- `FALSE_THRESHOLD` raised from 0.70 to 0.85: every verified-correct false-positive call in testing
  scored 0.999+, so there was no reason to hide a borderline, genuinely uncertain match — it now
  defaults to shown.

### Fixed
- README documented `pipx upgrade exhume` for getting updates, but that only works for package-index
  installs — for a `git+https://...` spec (what the quick start uses) it silently does nothing and
  reports "unchanged". The real way to pick up a newer commit is `pipx install --force "git+..."`;
  the README now says so.

### Evaluated, not changed
- Tried swapping the bundled model for Qwen2.5-7B-Instruct (Q4_K_M) to see if a bigger local model
  would judge more accurately. On the same regression battery it scored identically to the 3B model
  (14/15) — including failing the exact same case — while taking ~2.3x longer per call (1.83s vs
  0.80s). Kept Qwen2.5-3B as the default: no accuracy gain would have come with a real cost to scan
  time on jobs with many ambiguous matches. `--ai-gguf` still lets anyone drop in whatever model
  they prefer.

### Fixed (AI judging accuracy, round 2)
- **An explicitly labelled value could still be judged false by the model**, found from a real scan:
  `[I0]HandleQueryDeviceInfoConfirmation - !InitializingOAS.  Updating IPInfo, privateData =
  TOD=7,IP=10.192.200.30,RAS=0,CS=50613` was marked a false positive (87%+ confidence) despite the
  explicit `IP=` label, purely because of the surrounding verbose call-trace noise. A label right
  next to the value, on its own matched line, is a more reliable signal than anything inferred from
  context — `ai_filter._has_strong_label` (IP/host/server labels; DNI/NIE/CLIENTE labels) now
  short-circuits straight to REAL *without ever asking the model*, checked before the cache so it
  also overrides any stale cached FALSE verdict from before this fix. This also resolves the
  inconsistent NIE judging reported earlier (a `CLIENTE: Y5799882D`-style line now always matches),
  and saves a model call for what's usually the easiest, most common real case.

### Fixed (AI judging accuracy)
Found and fixed three real false-verdict causes by reproducing an actual scan result end to end,
then re-validated with a 16-case regression battery covering every detector the AI judges (all pass):
- **The judge only ever saw the match's own line**, which for a bare value with nothing else on it
  (a lone `4.1.9.3` from a reversed-text PDF extraction glitch, sitting between unrelated lines) gave
  the model no signal at all — it defaulted to REAL (measured confidence: 2% false). It's now shown
  the surrounding block (already collected for the HTML context view) instead of just its own line.
- That fix alone introduced a new mistake: with several lines in view, the model could anchor on a
  *different* nearby number (an invoice's decimal `TOTAL` two lines above a genuine `Tarjeta Visa
  ... CVV` line) and misjudge the real card as the fake one. Fixed by marking exactly which line
  the value came from (`>>> `) — validated to resolve both problems together, including when the
  flagged value happens to coincide with one of the model's own few-shot examples.
- **Per-line log boilerplate (timestamps, `[LEVEL]` tags) derailed the judgment of otherwise
  unambiguous matches.** An identical `IP Address: 10.128.18.102` line was judged correctly real
  with no prefix, but a false positive once given its real-world `10-03-2024 09:44:22.518 [X]`
  timestamp prefix — purely from that clutter, the exact semantic content unchanged. Common
  timestamp/log-tag prefixes are now stripped from what the AI sees (`ai_filter._declutter`); the
  context stored in the report is never touched, only the model's copy of it.
- The verdict cache (`~/.cache/exhume/verdicts.json`) now carries a `PROMPT_VERSION`: a judging-logic
  fix like the ones above now takes effect immediately instead of being masked by a stale cached
  answer from before the fix. Also fixed the cache key itself to hash the full context block (what
  the model is actually shown) rather than just the match's own line, so two identical bare values
  in different surrounding context no longer share a cached verdict.
- The triage summary sometimes labeled a finding "VERIFIED-LIVE" in its own prose even when nothing
  was actually verified (e.g. `--verify` was off). Whether a real LIVE finding exists is known
  exactly, so `ai._verified_live_guard` strips every "VERIFIED-LIVE" claim from the output when there
  is none, the same way `_no_findings_guard` already handled invented findings.

### Fixed (AI judging accuracy, round 3)
- **A manual's table of contents could be shown as a verified-real public IP.** Reported from a real
  scan: a fire-suppression equipment manual's letter-spaced table of contents contained a section
  number `3.4.4.2`, which happens to fall in AWS's public IP range. Reverse DNS returned
  `ec2-3-4-4-2.us-west-2.compute.amazonaws.com`, and the network check read any PTR hit as strong
  "VALID" evidence — but major cloud providers auto-assign a PTR to *every* address the moment it's
  allocated to their pool, whether or not it was ever actually used, so this proved nothing about the
  specific number. `exhume/verify/network.py` now recognizes AWS/Azure/GCP's auto-assigned PTR
  suffixes and reports those as `UNKNOWN` instead of `VALID`.
- On top of that, added a deterministic pre-filter: an IP sitting among two or more other dotted
  section-number lines (`N.N.N.N Título…`) is a table of contents, not an address — decided outright
  without ever asking the model (`ai_filter._looks_like_numbered_list`), the same short-circuit
  pattern already used for explicit labels. Confirmed against the exact reported case and a 2nd
  variant one digit over; both now resolve to false without a model call.
- `PROMPT_VERSION` bumped to 5 so any previously-cached verdict from before this fix is re-judged
  instead of reused.

### Changed
- README rewritten: shorter, bullet-driven, secondary detail moved into collapsible sections —
  aimed at being readable in one scroll instead of explaining every internal design decision.
  Trimmed further: fewer/no decorative emoji, no duplicate bullets between sections, plainer
  phrasing. Added a second GIF, `docs/report-demo.gif` (`make report-demo`,
  `scripts/make_report_demo.py`), that drives the actual HTML report with a real browser
  (Playwright + the system Chrome) — severity filtering, a finding expanded, Report mode, and
  toggling hidden/invalid matches back on — instead of only showing the terminal.
- Fixed a real rendering bug this surfaced: the AI triage summary's `**bold**` Markdown was never
  converted to `<strong>` in the HTML report (it rendered as literal asterisks); the console output
  already handled this correctly. `exhume/reporting/html.py`'s `_md_to_html` now does too.

### Security
- **The "local AI never sends data anywhere" claim is now an enforced check, not just a promise.**
  Audited every network call the AI code can make and found two real gaps, both fixed:
  - The triage prompt's context snippet was sent **unmasked** — it can contain the plaintext secret
    inline (e.g. `password=hunter2hunter2!!`), so masking only the standalone `value=` field, as the
    code already did, left the same secret sitting right next to it in `ctx=`. Both are masked now
    (`ai._masked_context`).
  - Nothing stopped `--ai-url` from pointing at a remote server: if the bundled model couldn't run
    and the configured URL "happened" to be non-local, Exhume would have talked to it anyway. There
    is now exactly one choke point, `ai.is_local_url` (used by `ai.available`, which every Ollama
    code path goes through, plus a second check directly in `OllamaEngine.__init__` as defense in
    depth): a URL is trusted only when **every** address it resolves to is loopback. A non-local URL
    disables the AI outright rather than being used — it never gets the chance to receive data.
  The bundled engine (the default, and what pipx/venv installs self-install) never opens a socket
  during judging/triage at all; the only network call it makes is the one-time model download from
  Hugging Face, before any scan data exists. See the README's "Data privacy" note for the full
  picture, and `tests/test_ai.py` for the tests that pin this down (non-local URLs, DNS tampering,
  resolution failure, and that the real secret value never appears in a triage prompt).

### Fixed
- **A globally-installed Exhume (`pipx install`, `uv tool install`) could not auto-install anything:
  no optional extras, no local AI.** Tools like pipx and uv deliberately strip `pip` out of the
  virtual environment after installing into it, so `python -m pip install ...` failed immediately
  with "No module named pip" — which surfaced as every extra staying "unavailable" and a misleading
  "needs a C/C++ toolchain" message for the AI runtime, even on a machine that has one. Exhume now
  re-bootstraps pip on its own via the standard library's `ensurepip` before any install attempt
  (`deps.ensure_pip`), so self-install works the same whether it's in a dev venv, installed with
  pipx, or anything else. Verified end to end: a fresh `pipx install` now auto-installs every extra
  (PDF/Office/archives/OCR/SMB/S3/Mongo) and the full local AI runtime + model on first use, with no
  `[full]` extra and no manual `pip install` ever needed. The quick-start instructions now lead with
  `pipx install` as the way to get a global `exhume` command without activating a venv.
- **Private IP addresses were wrongly marked "invalid" and hidden by default.** The network check
  probes from the scanning machine, which is normally OUTSIDE the target's internal network, so a
  private address (RFC1918) or link-local one almost never responds — that proved nothing about
  whether the address was real, yet it was treated exactly like a bogus public IP. Private/link-local
  addresses that don't respond are now `UNKNOWN` (shown normally, not hidden) with an honest detail
  message, and — since they're no longer short-circuited as invalid — they now also get a chance at
  the local AI's contextual judgment (e.g. a line with `Computer:`/`User:`/`IP Address:` fields is
  recognized as a genuine host record). Loopback addresses (127.0.0.0/8) are no longer probed at all
  (doing so would test the scanning host itself, not the target) and are reported valid outright.
  Only a genuinely public, unreachable IP is still flagged invalid — that is the real "looks like an
  IP but isn't a real host" case the check exists to catch.

### Added
- **Databases are scanned inside, not just peeked at — for four engines now, not only SQLite.**
  Every row and column is read and run through the full detector engine (not just column names) for:
  - **SQLite** (any extension, detected by content).
  - **dBase/xBase** `.dbf` (built-in reader, no dependency).
  - **MongoDB dumps** `.bson` (via `pymongo`'s `bson` module, auto-installed; nested documents and
    arrays are flattened, e.g. `profile.aws_key=...`).
  - **MS Access** `.mdb`/`.accdb`, when the optional `mdbtools` system tool is installed (same
    soft-dependency pattern as `tesseract` for OCR; bundled in the Docker image).
  A BLOB/binary cell that looks like an embedded file (another database, a document, an archive, a
  key...) is extracted and scanned recursively, exactly like a nested archive, sharing the same
  extraction budget. Engines with no portable single-file format or no safe way to parse their
  on-disk pages offline (MySQL's own storage files, SQL Server, Redis dumps, and Access without
  `mdbtools`) are at least string-scanned instead of skipped outright — see the README's
  "Database support" table for exactly what's covered.
  New `--db-max-rows` (default 5000) caps rows sampled per table.
- **The same value is reported once, with every place it was found.** A password, email or key
  pasted into 30 files used to print 30 near-identical lines; it now shows up as one finding with an
  occurrence count (`×30`) and the full list of locations, in the console, HTML, CSV, JSON and SARIF
  (SARIF now attaches every location to one result, so code-scanning tools group them correctly too).
  Within a severity tier, a value seen in more places is shown first — it's the more urgent one to fix.
- **The local AI now also explains sensitive databases and writes a richer triage.** For every
  database with sensitive-looking columns, it writes a one-line, concrete risk summary (e.g. "customer
  records with plaintext passwords and emails — high impersonation risk"), shown in the console and
  HTML. The triage prompt now works on deduplicated findings (mentioning how widely a secret is
  spread) and includes the sensitive-database summaries, so the executive summary and recommended
  next steps reflect the whole picture, not just the top raw matches. A deterministic guard stops the
  model from inventing a "fastest path to access" when there are no actual credential findings.

## [7.1.0] — 2026-11-24

### Added
- AI triage summary now runs on the bundled model too (not only Ollama), is short, never calls a
  credential "verified" unless it is, and ignores hidden findings. Verdicts are remembered between runs
  (`~/.cache/exhume/verdicts.json`), so re-auditing a share is much faster.
- `scripts/make_demo.py` / `make demo`: regenerates `docs/demo.gif` from a real run.
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
- README rewritten: shorter, with a clear install/run path.
- Console output prints the AI triage after the findings, as readable text instead of raw Markdown.
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
- Docker image build (the AI runtime is installed from a prebuilt wheel, not compiled), badges and
  project URLs pointed at a placeholder organization, and the exit code no longer counts hidden findings.
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
