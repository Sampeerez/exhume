"""Local-AI judgement of findings: is each match REAL data or a false positive?

Regexes and checksums only know that a string *looks* right. Whether ``3.2.2.1`` is an
IP address or a manual's section number, or ``4749999999999994`` a card or an invoice
total, depends on the surrounding text, and that is what a language model is good at.

Engines (first one that works wins):

1. **Bundled**: a small open model (Qwen2.5-3B-Instruct, Q4) run in-process with
   ``llama-cpp-python``. Exhume installs the package and downloads the model by itself
   on first use (~2.1 GB, cached in ``~/.cache/exhume``); nothing else has to be installed.
2. **Ollama**, if a local server is already running.

Privacy: everything runs on this machine. The only network traffic is the one-time
download of the model file from Hugging Face (no scan data is sent).

Cost control: matches that already failed their offline/network check are not judged,
identical values/contexts are judged once, and inside one (file, detector) group the
remaining matches inherit the verdict when the first samples all agree.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

from .console import Colors, eprint
from .models import FileResult, Finding, Verified

MODEL_URL = ("https://huggingface.co/Qwen/Qwen2.5-3B-Instruct-GGUF/resolve/main/"
             "qwen2.5-3b-instruct-q4_k_m.gguf")
MODEL_FILE = "qwen2.5-3b-instruct-q4_k_m.gguf"
MODEL_MIN_BYTES = 2_000_000_000
FALSE_THRESHOLD = 0.85   # confidence needed before a match is hidden as a false positive — every
# verified-correct FALSE case in testing scores 0.999+, so this is set well below that margin; a
# borderline, genuinely uncertain case now defaults to shown (unhidden) rather than hidden, in
# line with "dropping a real finding is worse than keeping a noisy one" (see LlamaEngine.ask).
# Bumped whenever the judging prompt/shots/context strategy changes materially: it's baked into
# the verdict cache key, so an improvement (or a fix to a bad verdict) takes effect immediately
# instead of being masked by a stale cached answer from the old prompt.
PROMPT_VERSION = 4

# Detectors whose matches are ambiguous without context. Provider-specific tokens
# (AWS, GitHub, ...) and live-verified credentials are never second-guessed.
JUDGED = {
    "Public IPv4", "Private IP (RFC1918)", "IPv6 address", "Credit card", "IBAN",
    "Spanish DNI/NIF", "Spanish NIE", "US SSN", "Phone number",
    "Credential assignment", "Credential in XML/property",
}
_JUDGED_PREFIX = ("High-entropy string",)

_GUIDE = {
    "Public IPv4": "a network IP address of a host, server, router or device",
    "Private IP (RFC1918)": "a network IP address of a host, server, router or device",
    "IPv6 address": "a network IPv6 address of a host, server, router or device",
    "Credit card": "a payment card number (PAN)",
    "IBAN": "a bank account number (IBAN)",
    "Spanish DNI/NIF": "the national ID number of a person",
    "Spanish NIE": "the foreigner ID number of a person",
    "US SSN": "a US social security number",
    "Phone number": "a real phone number belonging to a person or organization",
    "Credential assignment": "an actual password / secret value that someone set",
    "Credential in XML/property": "an actual password / secret value that someone set",
    "secret": "a real secret key or token",
}
_SYSTEM = (
    "You review matches from a sensitive-data scanner during an authorized security audit. "
    "Decide from the surrounding text whether the value is genuinely the kind of data the scanner "
    "claims (REAL), or a false positive such as a version, section number, price, total, reference, "
    "serial number, placeholder or garbled data (FALSE). Reply with exactly one word: REAL or FALSE."
)

_Q = ("Value: {v}\nText around it:\n---\n{c}\n---\n"
      "Is the value genuinely the claimed data (REAL) or a false positive (FALSE)?")
_Q_MARKED = ("Value: {v}\nText around it (the line marked >>> is where the value was found):\n---\n{c}\n---\n"
            "Is the value genuinely the claimed data (REAL) or a false positive (FALSE)?")

# (value, surrounding text, answer) examples shown to the model before the real question
_SHOTS = {
    "ip": [("10.158.14.103", "servidor sql 10.158.14.103 puerto 1433", "REAL"),
           ("3.2.2.1", "3.2.2.1 Seguridad en el almacén", "FALSE"),
           ("192.168.1.10", "ssh admin@192.168.1.10", "REAL"),
           ("2.7.5.4", "Versión del firmware 2.7.5.4 instalada", "FALSE"),
           ("2001:db8::1", "interfaz eth0 inet6 2001:db8::1/64 scope global", "REAL"),
           ("8::", "H,@/@q@8::@_@@@ (datos binarios sin sentido)", "FALSE")],
    "card": [("4539148803436467", "Tarjeta Visa 4539 1488 0343 6467 caduca 12/27", "REAL"),
             ("412499999999994", "TOTAL 62.412499999999994", "FALSE"),
             ("537499999999994", "PRECIO STOCK 537499999999994", "FALSE"),
             ("5500000000000004", "Pago con tarjeta Mastercard 5500 0000 0000 0004 CVV 123", "REAL")],
    "iban": [("ES9121000418450200051332", "Transferencia a la cuenta IBAN ES91 2100 0418 4502 0005 1332", "REAL"),
             ("ES9121000418450200051332", "Pedido ES9121000418450200051332-2024 lote 5", "FALSE"),
             ("ES7921000813610123456789", "Datos bancarios: ES79 2100 0813 6101 2345 6789 (La Caixa)", "REAL"),
             ("ES7921000813610123456789", "ref. interna ES7921000813610123456789.pdf", "FALSE")],
    "id": [("12345678Z", "DNI del titular: 12345678Z", "REAL"),
           ("12345678Z", "Ref. pedido 12345678Z-2024-001", "FALSE"),
           ("12345678Z", "Juan Pérez García, NIF 12345678Z, calle Mayor 3", "REAL"),
           ("87654321X", "código de lote 87654321X", "FALSE")],
    "cred": [("Sup3rS3cret!2024", "db_password = 'Sup3rS3cret!2024'", "REAL"),
             ("[Password]", "; Password=[Password]", "FALSE"),
             ("Winter2024!", "usuario: admin  contraseña: Winter2024!", "REAL"),
             ("password", "Introduzca su password para continuar", "FALSE")],
    "secret": [("kJ8sd9Fh2Lq0Zx7Vb3Nm1Pw5Rt6Yu4", "api_key=kJ8sd9Fh2Lq0Zx7Vb3Nm1Pw5Rt6Yu4", "REAL"),
               ("3f7a9c1d5e8b2f4a6c0d9e1b7a3f5c82", "sha256 checksum 3f7a9c1d5e8b2f4a6c0d9e1b7a3f5c82", "FALSE")],
    "phone": [("612345678", "Móvil de contacto: 612345678", "REAL"),
              ("912345678", "Teléfono: +34 912 345 678 (atención al cliente)", "REAL"),
              ("20240115", "Fecha pedido 20240115 referencia interna", "FALSE"),
              ("123456789", "ID de sesión 123456789 expira en 10 min", "FALSE")],
}
_DIGITS = re.compile(r"\d+")
_PROMPT_CTX_CAP = 1200
_SAMPLE_BEFORE_PROPAGATE = 3
_GROUP_FULL_LIMIT = 5      # groups up to this size are always judged item by item
_GROUP_HARD_CAP = 40       # max items judged per (file, detector) group


# ---------------------------------------------------------------- engines

def home_dir() -> Path:
    return Path(os.environ.get("EXHUME_HOME") or os.path.join(os.path.expanduser("~"), ".cache", "exhume"))


def cache_dir() -> Path:
    return home_dir() / "models"


class VerdictCache:
    """Remembers decisive verdicts between runs (re-audits of the same share are much faster)."""

    def __init__(self, model: str):
        self.model = model
        self.path = home_dir() / "verdicts.json"
        self.data: dict[str, str] = {}
        self.dirty = False
        try:
            self.data = json.loads(self.path.read_text())
        except Exception:
            self.data = {}

    def key(self, f: Finding) -> str:
        # Keyed on the same text the model is actually shown (the whole block, not just the
        # match's own line) — two identical bare values with different surrounding context are
        # different questions and must not share a cached answer.
        block = "\n".join(t for _, t in (f.context_block or [])) or f.context or ""
        raw = f"v{PROMPT_VERSION}|{self.model}|{_kind(f)}|{f.secret}|{block[:400]}"
        return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()

    def get(self, f: Finding) -> str | None:
        return self.data.get(self.key(f))

    def put(self, f: Finding, verdict: str) -> None:
        self.data[self.key(f)] = verdict
        self.dirty = True

    def save(self) -> None:
        if not self.dirty:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data))
            os.replace(tmp, self.path)
        except OSError:
            pass


class LlamaEngine:
    name = "bundled Qwen2.5-3B"

    def __init__(self, model_path: str):
        from llama_cpp import Llama  # type: ignore
        self._llm = Llama(model_path=model_path, n_ctx=4096, n_threads=os.cpu_count() or 4,
                          n_gpu_layers=-1, verbose=False)
        self._real = self._llm.tokenize(b"REAL", add_bos=False)[0]
        self._false = self._llm.tokenize(b"FALSE", add_bos=False)[0]
        self._fmt = None
        try:
            from llama_cpp.llama_chat_format import Jinja2ChatFormatter  # type: ignore
            tpl = self._llm.metadata.get("tokenizer.chat_template")
            if tpl:
                self._fmt = Jinja2ChatFormatter(template=tpl, eos_token="<|im_end|>", bos_token="")
        except Exception:
            self._fmt = None

    def _prompt(self, messages: list[dict]) -> str:
        if self._fmt:
            try:
                return self._fmt(messages=messages).prompt
            except Exception:
                pass
        out = "".join(f"<|im_start|>{m['role']}\n{m['content']}<|im_end|>\n" for m in messages)
        return out + "<|im_start|>assistant\n"

    def ask(self, system: str, user: str, shots: tuple = ()) -> str:
        """Return "FALSE" only when the model is clearly confident; otherwise "REAL".

        Dropping a real finding is worse than keeping a noisy one, so the verdict is read from the
        probabilities of the first answer token: FALSE needs FALSE_THRESHOLD of the REAL/FALSE mass.
        """
        return "FALSE" if self.p_false(system, user, shots) >= FALSE_THRESHOLD else "REAL"

    def generate(self, system: str, user: str, max_tokens: int = 500) -> str:
        """Free-form generation (used for the triage summary)."""
        self._llm.reset()
        out = self._llm.create_chat_completion(
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            max_tokens=max_tokens, temperature=0.2)
        self._llm.reset()
        return out["choices"][0]["message"]["content"]

    def _eval_cached(self, text: str) -> None:
        """Evaluate *text*, reusing the KV cache of the shared (system + examples) prefix."""
        llm = self._llm
        cut = text.rfind("<|im_start|>user")
        prefix, suffix = (text[:cut], text[cut:]) if cut > 0 else ("", text)
        if prefix:
            ptoks = llm.tokenize(prefix.encode(), add_bos=False, special=True)
            if (llm.n_tokens >= len(ptoks)) and list(llm._input_ids[:len(ptoks)]) == ptoks:
                llm.n_tokens = len(ptoks)          # rewind to the cached prefix
            else:
                llm.reset()
                llm.eval(ptoks)
            llm.eval(llm.tokenize(suffix.encode(), add_bos=False, special=True))
        else:
            llm.reset()
            llm.eval(llm.tokenize(text.encode(), add_bos=False, special=True))

    def p_false(self, system: str, user: str, shots: tuple = ()) -> float:
        import math

        import numpy as np
        messages = [{"role": "system", "content": system}]
        for q, a in shots:
            messages += [{"role": "user", "content": q}, {"role": "assistant", "content": a}]
        messages.append({"role": "user", "content": user})
        self._eval_cached(self._prompt(messages))
        logits = np.ctypeslib.as_array(self._llm._ctx.get_logits(), shape=(self._llm.n_vocab(),))
        a, b = float(logits[self._real]), float(logits[self._false])
        m = max(a, b)
        pr, pf = math.exp(a - m), math.exp(b - m)
        return pf / (pr + pf)


class OllamaEngine:
    def __init__(self, url: str, model: str):
        # Belt-and-suspenders: callers are expected to have already gone through
        # ai.available(), which rejects a non-local URL before this is ever constructed, but
        # this engine is the one thing in the whole codebase that can put audit data on a
        # socket, so it refuses to exist pointed anywhere but this machine, full stop.
        from .ai import is_local_url
        if not is_local_url(url):
            raise ValueError(f"refusing to use a non-local Ollama URL: {url!r}")
        self.url, self.model = url.rstrip("/"), model
        self.name = f"Ollama {model}"

    def generate(self, system: str, user: str, max_tokens: int = 500) -> str:
        body = json.dumps({"model": self.model, "stream": False, "prompt": f"{system}\n\n{user}",
                           "options": {"temperature": 0.2, "num_predict": max_tokens}}).encode()
        req = urllib.request.Request(self.url + "/api/generate", data=body,
                                     headers={"Content-Type": "application/json"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=180) as r:
            return json.loads(r.read()).get("response", "")

    def ask(self, system: str, user: str, shots: tuple = ()) -> str:
        examples = "".join(f"{q}\nAnswer: {a}\n\n" for q, a in shots)
        body = json.dumps({"model": self.model, "stream": False, "prompt": f"{system}\n\n{examples}{user}",
                           "options": {"temperature": 0, "num_predict": 4}}).encode()
        req = urllib.request.Request(self.url + "/api/generate", data=body,
                                     headers={"Content-Type": "application/json"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=60) as r:
            return json.loads(r.read()).get("response", "")


def _download(url: str, dest: Path) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_suffix(dest.suffix + ".part")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "exhume-model-fetch"})
        with urllib.request.urlopen(req, timeout=60) as r, open(part, "wb") as f:
            total = int(r.headers.get("Content-Length") or 0)
            done = 0
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                if total and (done // (1 << 20)) % 10 == 0:
                    eprint(f"\r{Colors.GR}  downloading model {done / 1e6:,.0f}/{total / 1e6:,.0f} MB "
                           f"({done * 100 // total}%){Colors.END}", end="")
        eprint("")
        if total and done != total:
            return False
        os.replace(part, dest)
        return True
    except Exception as exc:
        eprint(f"\n{Colors.Y}Model download failed: {exc}{Colors.END}")
        return False


def _install_llama_cpp() -> bool:
    import importlib

    from .deps import ensure_pip, pip_install
    eprint(f"{Colors.CY}Installing the local AI runtime (llama-cpp-python, first run only; this can "
           f"take a few minutes)...{Colors.END}")
    if not ensure_pip():
        return False
    index = "metal" if sys.platform == "darwin" else "cpu"
    ok = _pip_with_index(index) or pip_install("llama-cpp-python", timeout=1800)
    importlib.invalidate_caches()
    return ok


def _pip_with_index(index: str) -> bool:
    import subprocess
    cmd = [sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check",
           "--prefer-binary", "--only-binary=llama-cpp-python", "--extra-index-url",
           f"https://abetlen.github.io/llama-cpp-python/whl/{index}", "llama-cpp-python"]
    for extra in ([], ["--break-system-packages"]):
        try:
            if subprocess.run(cmd + extra, capture_output=True, timeout=600).returncode == 0:
                return True
        except Exception:
            continue
    return False


def load_engine(autoinstall: bool = True, gguf: str = "", ollama_url: str = "",
                ollama_model: str = "") -> object | None:
    """Return a ready engine or None (with a message explaining why)."""
    try:
        import llama_cpp  # type: ignore  # noqa: F401
        have = True
    except Exception:
        have = False
    if not have and autoinstall:
        from .deps import _pip_available
        have = _install_llama_cpp()
        if not have:
            why = ("pip is unavailable in this Python and couldn't be bootstrapped" if not _pip_available()
                  else "no prebuilt wheel and no C/C++ toolchain on this Python")
            eprint(f"{Colors.Y}Could not install llama-cpp-python ({why}); trying Ollama instead.{Colors.END}")
    if have:
        path = Path(gguf) if gguf else cache_dir() / MODEL_FILE
        if not path.exists() or path.stat().st_size < MODEL_MIN_BYTES:
            if gguf or not autoinstall:
                eprint(f"{Colors.Y}AI model not found at {path}.{Colors.END}")
            else:
                eprint(f"{Colors.CY}Downloading the local AI model (~2.1 GB, one time, from "
                       f"Hugging Face)...{Colors.END}")
                if not _download(MODEL_URL, path):
                    path = None  # type: ignore[assignment]
        if path and path.exists():
            try:
                return LlamaEngine(str(path))
            except Exception as exc:
                eprint(f"{Colors.Y}Could not start the bundled model: {exc}{Colors.END}")
    # Fallback: an Ollama server the user already runs.
    from .ai import available
    url = ollama_url or "http://localhost:11434"
    models = available(url)
    if models:
        return OllamaEngine(url, ollama_model or models[0])
    return None


# ---------------------------------------------------------------- judging

def _kind(f: Finding) -> str:
    d = f.detector
    if "IPv4" in d or "IP (" in d or d == "IPv6 address":
        return "ip"
    if d == "Credit card":
        return "card"
    if d == "IBAN":
        return "iban"
    if d.startswith(("Spanish", "US SSN")):
        return "id"
    if d == "Phone number":
        return "phone"
    if d.startswith("High-entropy"):
        return "secret"
    return "cred"


def _is_judged(f: Finding) -> bool:
    if f.verified in (Verified.INVALID, Verified.LIVE) or f.ai_verdict:
        return False
    return f.detector in JUDGED or f.detector.startswith(_JUDGED_PREFIX)


def _claim(f: Finding) -> str:
    return _GUIDE.get(f.detector) or _GUIDE["secret"]


def _shots(f: Finding) -> tuple:
    # Shot examples stay single-line/unmarked — they're already unambiguous by construction (the
    # whole point is the model learns the REAL/FALSE pattern from them), and marking a short shot
    # line identically to how the real multi-line question is marked makes one of them (the
    # "looks like a section number" example) a near-exact duplicate of a real-world case that uses
    # the same wording, which measurably confused the model in testing. The real question's own
    # marking (see _marked_block) is what matters for the cases that actually need it.
    claim = _claim(f)
    return tuple((f"The scanner flagged this value as {claim}.\n" + _Q.format(v=v, c=c), ans)
                 for v, c, ans in _SHOTS[_kind(f)])


# Common log-line boilerplate (timestamps, "[LEVEL]" tags) that carries no judging signal but,
# left in, measurably distracts the model — a real "IP Address: 10.128.18.102" line in a timestamped
# log was judged false positive purely because of the "10-03-2024 09:44:22.518 [X]" clutter in front
# of it; stripped, the identical line is judged correctly. This only affects what the AI sees, never
# the context stored in the report.
_LOG_PREFIX = re.compile(
    r"^\s*(?:\d{4}-\d{2}-\d{2}[ T]\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?|"
    r"\d{1,2}[-/]\d{1,2}[-/]\d{2,4}[ T]\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?)\s*"
    r"(?:\[[^\]\n]{0,24}\])?\s*(?:\[[^\]\n]{0,24}\])?\s*"
)


def _declutter(line: str) -> str:
    cleaned = _LOG_PREFIX.sub("", line)
    return cleaned if cleaned.strip() else line


def _marked_block(f: Finding) -> str:
    """The surrounding lines (already collected for the HTML context view) with the matched line
    itself marked ">>> ". Two things that otherwise pull against each other both need this:

    - The match's own line is sometimes just the bare value with nothing else on it (a lone
      "4.1.9.3"); with no other signal the model has nothing to judge and defaults to REAL. The
      surrounding lines give it the one thing that actually settles these — does the text read
      like network/financial documentation, or like a manual, a table, unrelated prose?
    - But showing several lines at once risks the model anchoring on a DIFFERENT, nearby number
      (e.g. an invoice's fake-looking TOTAL two lines above a genuine "Tarjeta Visa ... CVV" line)
      and judging the wrong one. Marking exactly which line the value came from fixes that without
      giving up the surrounding context — tested to correctly separate both cases at once.
    """
    block = f.context_block or []
    if not block:
        return _declutter(f.context) if f.context else ""
    return "\n".join((">>> " if n == f.line else "    ") + _declutter(t) for n, t in block)


def _prompt(f: Finding) -> str:
    lines = _marked_block(f)[:_PROMPT_CTX_CAP]
    return f"The scanner flagged this value as {_claim(f)}.\n" + _Q_MARKED.format(v=f.secret or f.redacted, c=lines)


def _parse(answer: str) -> str | None:
    a = (answer or "").strip().upper()
    if a.startswith("REAL"):
        return "real"
    if a.startswith("FALSE") or a.startswith("FAKE") or a.startswith("NO"):
        return "false"
    return None


# A label sitting right next to the value, on its own matched line, is a stronger signal than
# anything the model infers from the surrounding noise — an explicit "IP=10.192.200.30" inside a
# verbose state-machine trace ("> OnQueryDeviceInfoConfirmation", "< HandleQueryDeviceInfo...") was
# measured to confuse the model into FALSE (87%+ confidence) purely from that unrelated clutter,
# despite the label being right there. Checked deterministically, on the matched line only (not the
# whole block, so an unrelated label two lines away doesn't count), before ever asking the model —
# this also saves a call for what is usually the easiest, most common real case.
_STRONG_LABEL = {
    "ip": re.compile(r"(?i)\b(?:ip|ipv4|ipv6|ip\s*address|direcci[oó]n\s*ip|host(?:name)?|"
                     r"servidor|server)\b\s*[:=]"),
    "id": re.compile(r"(?i)\b(?:dni|nif|nie|cliente|titular|customer)\b\s*[:=]"),
}


def _own_line(f: Finding) -> str:
    return next((t for n, t in (f.context_block or []) if n == f.line), f.context or "")


def _has_strong_label(f: Finding) -> bool:
    pat = _STRONG_LABEL.get(_kind(f))
    return bool(pat and pat.search(_own_line(f)))


def _ctx_key(f: Finding) -> tuple:
    return (f.detector, _DIGITS.sub("#", f.context or "")[:160], os.path.splitext(f.path)[1].lower())


def _label(f: Finding, verdict: str, how: str) -> None:
    f.ai_verdict = verdict
    f.ai_note = how


def judge(results: list[FileResult], engine, max_calls: int = 4000) -> dict:
    """Judge ambiguous findings in place. Returns counters for reporting."""
    cand = [f for r in results for f in r.findings if _is_judged(f)]
    stats = {"candidates": len(cand), "asked": 0, "cached": 0, "labeled": 0, "real": 0, "false": 0,
             "inherited": 0, "skipped": 0}
    if not cand:
        return stats
    # most severe / most relevant first so the call budget is spent where it matters
    cand.sort(key=lambda f: (-int(f.severity), f.path, f.line))
    groups: dict[tuple, list[Finding]] = {}
    for f in cand:
        groups.setdefault((f.path, f.detector), []).append(f)

    by_value: dict[tuple, str] = {}
    by_ctx: dict[tuple, str] = {}
    name = getattr(engine, "name", "local AI")
    vcache = VerdictCache(name)
    t0 = time.monotonic()

    def ask(f: Finding) -> str | None:
        k1, k2 = (f.detector, f.secret), _ctx_key(f)
        hit = by_value.get(k1) or by_ctx.get(k2)
        if hit:
            return hit
        if _has_strong_label(f):
            stats["labeled"] += 1
            by_value[k1] = by_ctx[k2] = "real"
            _label(f, "real", "explicit label on its own line (e.g. IP=/DNI=) — not sent to the model")
            return "real"
        old = vcache.get(f)
        if old:
            stats["cached"] += 1
            by_value[k1] = by_ctx[k2] = old
            return old
        if stats["asked"] >= max_calls:
            return None
        stats["asked"] += 1
        if stats["asked"] % 25 == 0:
            rate = (time.monotonic() - t0) / stats["asked"]
            eprint(f"\r{Colors.GR}  AI judged {stats['asked']} matches ({rate:.2f}s each)...{Colors.END}", end="")
        try:
            v = _parse(engine.ask(_SYSTEM, _prompt(f), _shots(f)))
        except Exception:
            return None
        if v:
            by_value[k1] = by_ctx[k2] = v
            vcache.put(f, v)
        return v

    for items in groups.values():
        verdicts: list[str] = []
        limit = len(items) if len(items) <= _GROUP_FULL_LIMIT else _SAMPLE_BEFORE_PROPAGATE
        idx = 0
        while idx < len(items) and idx < limit:
            v = ask(items[idx])
            if v:
                if items[idx].ai_verdict is None:
                    _label(items[idx], v, f"judged by {name}")
                stats[v] += 1
                verdicts.append(v)
            else:
                stats["skipped"] += 1
            idx += 1
        rest = items[idx:]
        if not rest:
            continue
        if verdicts and len(set(verdicts)) == 1 and len(verdicts) >= _SAMPLE_BEFORE_PROPAGATE:
            for f in rest:      # homogeneous group: inherit (and still check cached identical values)
                if _has_strong_label(f):
                    stats["labeled"] += 1
                    _label(f, "real", "explicit label on its own line (e.g. IP=/DNI=) — not sent to the model")
                    v = "real"
                else:
                    v = by_value.get((f.detector, f.secret)) or verdicts[0]
                    _label(f, v, f"same as {len(verdicts)} sampled matches in this file ({name})")
                stats["inherited"] += 1
                stats[v] += 1
        else:                   # mixed group: judge individually up to the cap
            for f in rest[:max(0, _GROUP_HARD_CAP - idx)]:
                v = ask(f)
                if v:
                    if f.ai_verdict is None:
                        _label(f, v, f"judged by {name}")
                    stats[v] += 1
                else:
                    stats["skipped"] += 1
            stats["skipped"] += max(0, len(rest) - max(0, _GROUP_HARD_CAP - idx))
    eprint("")
    vcache.save()
    return stats


# ---------------------------------------------------------------- assets (databases / config files)

_ASSET_SYSTEM = (
    "You help an auditor decide which files found on a file share deserve attention. Decide from the "
    "file name, location and metadata whether the file is likely to hold credentials, personal or "
    "business data, or deployment/configuration details of interest. Reply with exactly one word: "
    "REAL (worth listing) or FALSE (noise)."
)
_ASSET_NOISE = (
    "OS/app housekeeping and caches (Thumbs.db, .DS_Store, desktop.ini, thumbnails, icon caches), "
    "browser/IDE/editor caches, build output, localization/resource/theme files, package or "
    "dependency metadata, sample/template files, logs of no value, and vendor program data"
)


def _a(tag: str, name: str, loc: str, ans: str) -> tuple:
    return (f"Type: {tag}\nFile: {name}\nLocation (tail): .../{loc}\n"
            "Worth an auditor's attention (REAL) or noise (FALSE)?", ans)


_ASSET_SHOTS = (
    _a("database", "Thumbs.db", "Fotos/Vacaciones", "FALSE"),
    _a("database", "clientes.db", "Contabilidad/Datos", "REAL"),
    _a("config", "app.config", "Servidor/ERP/bin", "REAL"),
    _a("config", "messages_es.properties", "Aplicacion/lib/i18n", "FALSE"),
    _a("config", "web.config", "inetpub/wwwroot", "REAL"),
    _a("config", "package-lock.json", "proyecto/web", "FALSE"),
    _a("database", "IconCache.db", "Users/Pepe/AppData", "FALSE"),
    _a("config", "settings.ini", "Backups/Servidor", "REAL"),
)


def _asset_prompt(r: FileResult, tag: str) -> str:
    tail = "/".join(r.path.replace(" ::> ", "/").split("/")[-4:])
    meta = f"Type: {tag}\nFile: {r.name}\nLocation (tail): .../{tail}\n"
    di = r.db_info or {}
    if di.get("tables"):
        meta += "Tables: " + ", ".join(f"{t['name']}({t.get('rows')})" for t in di["tables"][:12]) + "\n"
    if di.get("sensitive_columns"):
        meta += "Sensitive-looking columns: " + ", ".join(di["sensitive_columns"][:12]) + "\n"
    return meta + "Worth an auditor's attention (REAL) or noise (FALSE)?"


_INSIGHT_SYSTEM = (
    "You are a senior auditor summarizing a database found during an authorized security audit. "
    "In one short sentence (under 20 words), say what kind of real-world data the table likely holds "
    "and why it matters (e.g. \"customer records with plaintext passwords and emails — high "
    "impersonation risk\"). Be concrete, not generic. No preamble, no quotes, one sentence only."
)
_MAX_INSIGHT_DBS = 40


def _insight_prompt(r: FileResult) -> str:
    di = r.db_info or {}
    lines = [f"Database: {r.name}"]
    for t in di.get("tables", [])[:8]:
        cols = ", ".join(t.get("columns") or [])
        lines.append(f"- table {t['name']} ({t.get('rows')} rows): {cols}")
    sc = di.get("sensitive_columns") or []
    if sc:
        lines.append("Columns that look sensitive: " + ", ".join(sc[:10]))
    lines.append("One-sentence summary of what this data is and why it matters:")
    return "\n".join(lines)


def judge_db_insights(results: list[FileResult], engine, max_calls: int = _MAX_INSIGHT_DBS) -> int:
    """Ask the local AI what a sensitive database actually CONTAINS, for the report and the triage.

    Bounded and best-effort: skipped files just keep no ``ai_insight``. Only databases with at
    least one sensitive-looking column are worth the call (plain lookup tables are not).
    """
    targets = [r for r in results if "database" in r.tags and r.ai_verdict != "false"
              and (r.db_info or {}).get("sensitive_columns") and not (r.db_info or {}).get("ai_insight")]
    asked = 0
    for r in targets[:max_calls]:
        try:
            text = engine.generate(_INSIGHT_SYSTEM, _insight_prompt(r), max_tokens=60).strip()
        except Exception:
            continue
        asked += 1
        if text:
            r.db_info["ai_insight"] = text.strip(' "\n')[:220]
    return asked


def judge_assets(results: list[FileResult], engine, max_calls: int = 1500) -> dict:
    """Mark database/config assets the AI considers noise. One call per distinct (name, type)."""
    stats = {"asked": 0, "real": 0, "false": 0, "skipped": 0}
    cache: dict[tuple, str | None] = {}
    for r in results:
        tag = "database" if "database" in r.tags else "config" if "config" in r.tags else None
        if not tag or "sensitive_name" in r.tags or "key_material" in r.tags:
            continue          # secrets-looking names / keys are never hidden
        if (r.db_info or {}).get("sensitive_columns") or any(not f.hidden for f in r.findings):
            r.ai_verdict = "real"      # holds findings / sensitive columns: always worth listing
            stats["real"] += 1
            continue
        key = (tag, r.name.lower(), bool(r.db_info and r.db_info.get("tables")))
        if key not in cache:
            if stats["asked"] >= max_calls:
                stats["skipped"] += 1
                continue
            stats["asked"] += 1
            try:
                cache[key] = _parse(engine.ask(_ASSET_SYSTEM, _asset_prompt(r, tag), _ASSET_SHOTS))
            except Exception:
                cache[key] = None
        v = cache[key]
        if v:
            r.ai_verdict = v
            stats[v] += 1
        else:
            stats["skipped"] += 1
    return stats
