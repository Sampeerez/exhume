"""Optional local-AI triage of findings via Ollama.

The regex + entropy + live-verification core is what *finds* and *proves* secrets;
a local LLM is only used to *triage and prioritize* what was already found — to
answer "of these N findings, which are the fastest paths to access, and why".

Privacy, enforced, not just promised:
- Every value sent in the triage prompt is masked (``f.redacted``), and the surrounding context
  line has the real secret substituted out of it too — the prompt never contains a plaintext
  secret, a real card/IBAN number or a live credential, only its masked form and its shape.
- The only network destination is a local Ollama instance, and :func:`available` REFUSES to even
  try a URL that doesn't resolve to the loopback interface (127.0.0.0/8 / ::1 / "localhost") — so
  pointing ``--ai-url`` at a remote host does not leak data, it just disables Ollama. The call also
  bypasses any configured HTTP proxy, so it can't be silently rerouted off the machine either.
If no local model is reachable this silently returns None and the scan is unaffected. Enabled by
default; disable with --no-ai.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import urllib.error
import urllib.request
from urllib.parse import urlparse

from .console import Colors, eprint
from .models import FileResult, Verified, group_findings, group_sort_key

_CONNECT_TIMEOUT = 2
_GEN_TIMEOUT = 90
_MAX_FINDINGS = 80

_SYSTEM = (
    "You are a senior penetration tester triaging secret-scanner findings. "
    "Be concise, concrete and actionable. Never invent findings that are not listed."
)


def _opener():
    # Bypass any configured proxy: Ollama is strictly local.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _get(url: str, timeout: int):
    try:
        with _opener().open(urllib.request.Request(url), timeout=timeout) as r:
            return r.status, r.read()
    except Exception:
        return None, b""


def _post(url: str, body: dict, timeout: int):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with _opener().open(req, timeout=timeout) as r:
            return r.status, r.read()
    except Exception:
        return None, b""


def is_local_url(url: str) -> bool:
    """True only if *url*'s host resolves exclusively to a loopback address.

    This is the one technical control standing between "local AI" and "data leaves the
    machine": every caller that might hand real finding data to an Ollama server (this
    module's own triage prompt, and :mod:`exhume.ai_filter`'s engine fallback) goes through
    :func:`available`, which calls this first. A URL is trusted only when every address it
    resolves to is loopback — a single public/LAN address anywhere in the result is enough
    to reject it, so a DNS name that resolves to a mix of local and remote addresses is
    refused rather than guessed at.
    """
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return False
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass  # not a literal IP — it's a hostname, resolve it below
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    return bool(infos) and all(ipaddress.ip_address(info[4][0]).is_loopback for info in infos)


def available(ai_url: str) -> list[str]:
    """Return the list of local Ollama models, or [] if unreachable OR *ai_url* isn't local.

    Refusing a non-local URL here (rather than at the call site) protects every caller —
    this module's own :func:`triage` and :mod:`exhume.ai_filter`'s Ollama fallback alike —
    with a single check: no finding data is ever sent anywhere but this machine.
    """
    if not is_local_url(ai_url):
        eprint(f"{Colors.Y}--ai-url '{ai_url}' is not local; refusing to send audit data to it. "
               f"The local AI needs an Ollama instance on this machine (loopback only).{Colors.END}")
        return []
    st, raw = _get(ai_url.rstrip("/") + "/api/tags", _CONNECT_TIMEOUT)
    if st != 200:
        return []
    try:
        return [m["name"] for m in json.loads(raw).get("models", [])]
    except Exception:
        return []


def _masked_context(f) -> str:
    """The surrounding line with the real secret value substituted out of it — the context
    alone can contain the plaintext (e.g. "password=hunter2hunter2!!"), so masking only the
    standalone `value=` field and leaving this raw would defeat the point entirely."""
    ctx = (f.context or "").strip()[:160]
    if f.secret and f.secret in ctx:
        ctx = ctx.replace(f.secret, f.redacted)
    return ctx


def _build_prompt(results: list[FileResult]) -> str:
    # The same value seen in many places is one real-world issue, not several — the model
    # should talk about ONE leaked password used everywhere, not list it N times.
    findings = [f for r in results for f in r.findings if not f.hidden]
    groups = sorted(group_findings(findings), key=group_sort_key)
    lines = []
    for i, g in enumerate(groups[:_MAX_FINDINGS], 1):
        f = g.rep
        v = {Verified.LIVE: "VERIFIED-LIVE", Verified.DEAD: "dead"}.get(f.verified, "unverified")
        ctx = _masked_context(f)
        spread = f" (seen in {g.count} places)" if g.count > 1 else ""
        lines.append(f"{i}. [{f.severity.label}][{v}] {f.detector} @ {f.path}:{f.line}{spread} "
                     f"value={f.redacted} ctx={ctx!r}")
    listing = "\n".join(lines) if lines else "(no findings)"

    dbs = [r for r in results if "database" in r.tags and r.ai_verdict != "false"
          and (r.db_info or {}).get("sensitive_columns")]
    db_lines = []
    for r in dbs[:10]:
        di = r.db_info or {}
        insight = f" — {di['ai_insight']}" if di.get("ai_insight") else ""
        db_lines.append(f"- {r.path}: {', '.join(di.get('sensitive_columns', [])[:6])}{insight}")
    db_block = (f"\n\nDatabases with sensitive-looking columns ({len(dbs)} total):\n" + "\n".join(db_lines)
               if db_lines else "")

    overview = f"{len(groups)} unique finding(s) from {len(findings)} occurrence(s) across the target."
    return (
        f"{overview}\n\n"
        f"Findings from an authorized audit, highest priority first "
        f"(showing up to {_MAX_FINDINGS} unique values):\n{listing}{db_block}\n\n"
        "Rules: only findings tagged [VERIFIED-LIVE] are confirmed working; every other finding is "
        "UNVERIFIED and must be described as such. \"(seen in N places)\" means that exact value was "
        "found in N different locations — call out the blast radius for widely-repeated secrets. "
        "The findings list is the ONLY source of credentials/secrets — if it says '(no findings)', "
        "there are none: write exactly \"No credential findings.\" under Fastest paths to access and do "
        "not mention any specific column, table or value that isn't in the findings list above. "
        "Do not invent details that are not listed.\n"
        "Produce a SHORT report (under 180 words) with exactly these sections, in Markdown:\n"
        "## Executive summary\n(2-3 sentences: overall exposure and the riskiest data categories present.)\n"
        "## Fastest paths to access\n(At most 4 bullets, highest impact first — prefer "
        "VERIFIED-LIVE credentials and widely-repeated secrets — each one line.)\n"
        "## Recommended next steps\n(At most 4 bullets, concrete and prioritized.)\n"
    )


def _no_findings_guard(text: str, results: list[FileResult]) -> str:
    """Small models sometimes invent a plausible-looking credential finding when there are
    none to report (e.g. only a sensitive database, no actual secret). Since whether there
    ARE findings is known exactly (unlike the model's prose), enforce it deterministically
    rather than hope the prompt is obeyed."""
    if any(not f.hidden for r in results for f in r.findings):
        return text
    import re
    return re.sub(r"(?is)(##\s*fastest paths to access\s*\n).*?(?=\n##|\Z)",
                 r"\1No credential findings.\n", text)


def _verified_live_guard(text: str, results: list[FileResult]) -> str:
    """The model is instructed to call something "VERIFIED-LIVE" only when the input actually
    tagged it that way, but a small model sometimes uses the phrase anyway — e.g. because
    --verify was off, so nothing was ever checked, yet it still writes "VERIFIED-LIVE
    credential". Whether a real LIVE finding exists is known exactly; when there is none, strip
    every claim of one rather than let an unverified finding be reported as confirmed."""
    has_live = any(f.verified is Verified.LIVE and not f.hidden for r in results for f in r.findings)
    if has_live:
        return text
    import re
    return re.sub(r"(?i)\bVERIFIED[\s-]*LIVE\b", "UNVERIFIED", text)


def triage(results: list[FileResult], ai_url: str, model: str = "", engine=None) -> dict | None:
    """Run local triage. Returns {'model','summary'} or None if unavailable.

    With *engine* (the bundled model, see :mod:`exhume.ai_filter`) nothing else is needed;
    otherwise a running Ollama server is used.
    """
    if engine is not None and hasattr(engine, "generate"):
        try:
            text = engine.generate(_SYSTEM, _build_prompt(results), max_tokens=380).strip()
        except Exception:
            text = ""
        if text:
            text = _verified_live_guard(_no_findings_guard(text, results), results)
            return {"model": getattr(engine, "name", "local AI"), "summary": text}
    models = available(ai_url)
    if not models:
        return None
    chosen = model or models[0]
    st, raw = _post(
        ai_url.rstrip("/") + "/api/generate",
        {"model": chosen, "prompt": f"{_SYSTEM}\n\n{_build_prompt(results)}", "stream": False,
         "options": {"temperature": 0.2}},
        _GEN_TIMEOUT,
    )
    if st != 200:
        return None
    try:
        text = json.loads(raw).get("response", "").strip()
    except Exception:
        return None
    if not text:
        return None
    return {"model": chosen, "summary": _verified_live_guard(_no_findings_guard(text, results), results)}
