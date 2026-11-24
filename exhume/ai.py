"""Optional local-AI triage of findings via Ollama.

The regex + entropy + live-verification core is what *finds* and *proves* secrets;
a local LLM is only used to *triage and prioritize* what was already found — to
answer "of these N findings, which are the fastest paths to access, and why".

Privacy: this talks ONLY to a local Ollama instance (default http://localhost:11434)
and is sent **masked** values, never plaintext secrets. The call bypasses any HTTP
proxy. If no local model is reachable it silently returns None and the scan is
unaffected. Enabled by default; disable with --no-ai.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from .models import FileResult, Verified

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


def available(ai_url: str) -> list[str]:
    """Return the list of local Ollama models, or [] if unreachable."""
    st, raw = _get(ai_url.rstrip("/") + "/api/tags", _CONNECT_TIMEOUT)
    if st != 200:
        return []
    try:
        return [m["name"] for m in json.loads(raw).get("models", [])]
    except Exception:
        return []


def _build_prompt(results: list[FileResult]) -> str:
    findings = [f for r in results for f in r.findings if not f.hidden]
    findings.sort(key=lambda f: (f.verified is not Verified.LIVE, -int(f.severity)))
    lines = []
    for i, f in enumerate(findings[:_MAX_FINDINGS], 1):
        v = {Verified.LIVE: "VERIFIED-LIVE", Verified.DEAD: "dead"}.get(f.verified, "unverified")
        ctx = (f.context or "").strip()[:120]
        lines.append(f"{i}. [{f.severity.label}][{v}] {f.detector} @ {f.path}:{f.line} "
                     f"value={f.redacted} ctx={ctx!r}")
    listing = "\n".join(lines) if lines else "(no findings)"
    return (
        f"Findings from an authorized audit ({len(findings)} total, showing up to {_MAX_FINDINGS}):\n"
        f"{listing}\n\n"
        "Rules: only findings tagged [VERIFIED-LIVE] are confirmed working; every other finding is "
        "UNVERIFIED and must be described as such. Do not invent details that are not listed.\n"
        "Produce a SHORT report (under 150 words) with exactly these sections, in Markdown:\n"
        "## Executive summary\n(2 sentences on overall exposure.)\n"
        "## Fastest paths to access\n(At most 4 bullets, highest impact first — prefer "
        "VERIFIED-LIVE credentials — each one line.)\n"
        "## Recommended next steps\n(At most 3 bullets.)\n"
    )


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
    return {"model": chosen, "summary": text} if text else None
