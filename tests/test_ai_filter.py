from exhume import ai_filter
from exhume.detectors import scan_text
from exhume.models import FileResult, Finding, Severity, Verified


class FakeEngine:
    """Says FALSE for anything that looks like a section number, REAL otherwise."""
    name = "fake"

    def __init__(self):
        self.calls = 0

    def ask(self, system, user, shots=()):
        self.calls += 1
        return "FALSE" if "Value: 3.2.2" in user else "REAL"


def _results(texts, path="a.pdf"):
    out = []
    for i, t in enumerate(texts):
        fs = scan_text(t, 3.5)
        for f in fs:
            f.path = f"{path}{i}"
        out.append(FileResult(path=f"{path}{i}", name="x", ext=".pdf", size=1, findings=fs))
    return out


def test_judge_marks_false_and_real():
    res = _results(["3.2.2.1 Seguridad", "servidor 10.1.1.5"])
    stats = ai_filter.judge(res, FakeEngine())
    verdicts = {f.secret: f.ai_verdict for r in res for f in r.findings if f.detector.endswith("IPv4")
                or "IP" in f.detector}
    assert verdicts["3.2.2.1"] == "false" and verdicts["10.1.1.5"] == "real"
    assert stats["false"] == 1 and stats["real"] == 1
    assert next(f for r in res for f in r.findings if f.secret == "3.2.2.1").hidden


def test_homogeneous_group_inherits_after_sampling():
    text = "\n".join(f"3.2.2.{i} Seccion" for i in range(1, 30))
    res = _results([text], path="m.pdf")
    eng = FakeEngine()
    stats = ai_filter.judge(res, eng)
    assert eng.calls < 10          # not 29 calls
    assert stats["false"] == 29 and stats["inherited"] > 0


def test_invalid_and_provider_tokens_are_not_judged():
    res = _results(["4111111111111112"])          # fails Luhn -> already INVALID
    assert all(f.verified is Verified.INVALID for r in res for f in r.findings)
    eng = FakeEngine()
    ai_filter.judge(res, eng)
    assert eng.calls == 0


def test_parse_answers():
    assert ai_filter._parse("REAL") == "real"
    assert ai_filter._parse("false.") == "false"
    assert ai_filter._parse("maybe") is None


def test_noise_files_are_never_assets():
    from exhume.extractors.magic import classify
    assert classify("Thumbs.db", ".db", None) == []
    assert classify(".DS_Store", "", None) == []
    assert "database" in classify("clientes.db", ".db", None)


def test_judge_assets_hides_noise_and_keeps_sensitive():
    class E:
        name = "fake"

        def ask(self, system, user, shots=()):
            return "FALSE" if "messages.properties" in user else "REAL"

    noise = FileResult(path="/a/messages.properties", name="messages.properties", ext=".properties",
                       size=10, tags=["config"])
    keep = FileResult(path="/a/app.config", name="app.config", ext=".config", size=10, tags=["config"])
    secret = FileResult(path="/a/credentials.xml", name="credentials.xml", ext=".xml", size=10,
                        tags=["config", "sensitive_name"])
    st = ai_filter.judge_assets([noise, keep, secret], E())
    assert noise.ai_verdict == "false" and keep.ai_verdict == "real" and secret.ai_verdict is None
    assert st["asked"] == 2


def test_verdicts_are_remembered_between_runs():
    res = _results(["3.2.2.1 Seguridad"])
    first = FakeEngine()
    ai_filter.judge(res, first)
    assert first.calls == 1
    res2 = _results(["3.2.2.1 Seguridad"])
    second = FakeEngine()
    stats = ai_filter.judge(res2, second)
    assert second.calls == 0 and stats["cached"] == 1
    assert next(f for r in res2 for f in r.findings if f.secret == "3.2.2.1").ai_verdict == "false"


def test_triage_uses_bundled_engine_and_skips_hidden():
    from exhume import ai as ai_mod

    class G:
        name = "fake"
        prompt = ""

        def generate(self, system, user, max_tokens=500):
            G.prompt = user
            return "## Executive summary\nok"

    res = _results(["3.2.2.1 Seguridad", "servidor 10.1.1.5"])
    ai_filter.judge(res, FakeEngine())
    out = ai_mod.triage(res, "http://127.0.0.1:1", "", engine=G())
    assert out and out["model"] == "fake"
    assert "Private IP" in G.prompt           # the real (not hidden) finding is included
    assert "3.2.2.1" not in G.prompt          # hidden (AI-false) findings are not triaged
    assert "10.1.1.5" not in G.prompt         # the real IP value itself is never sent, only masked


def test_ollama_engine_refuses_non_local_url():
    import pytest as _pytest

    with _pytest.raises(ValueError, match="non-local"):
        ai_filter.OllamaEngine("http://10.0.0.5:11434", "llama3")


def test_ollama_engine_accepts_loopback_url():
    eng = ai_filter.OllamaEngine("http://127.0.0.1:11434", "llama3")
    assert eng.url == "http://127.0.0.1:11434"


def test_prompt_uses_full_surrounding_block_not_just_the_match_line():
    """A bare value alone on its line (e.g. a lone "4.1.9.3") gives the model nothing to judge —
    it needs the lines around it to tell a real IP from a reversed-PDF section number sitting in
    the middle of unrelated prose."""
    from exhume.detectors import scan_text
    text = "Página 13 de 13\nIntroducción\n4.1.9.3\nLongitud en metros\nde baja tensión."
    f = next(x for x in scan_text(text, 3.5) if x.detector == "Public IPv4")
    prompt = ai_filter._prompt(f)
    assert "Página 13 de 13" in prompt
    assert "Longitud en metros" in prompt
    assert "4.1.9.3" in prompt


def test_verdict_cache_key_depends_on_full_block_not_just_own_line():
    """Same bare value, same own line, DIFFERENT surrounding context -> different cache entries."""
    from exhume.detectors import scan_text
    real = next(x for x in scan_text("servidor\n4.1.9.3\npuerto 1433 abierto", 3.5)
               if x.detector == "Public IPv4")
    fake = next(x for x in scan_text("manual del producto\n4.1.9.3\nsección siguiente", 3.5)
               if x.detector == "Public IPv4")
    cache = ai_filter.VerdictCache("fake-model")
    assert cache.key(real) != cache.key(fake)


def test_declutter_strips_log_timestamps_but_keeps_content():
    line = "10-03-2024 09:44:22.518 [X]    IP Address: 10.128.18.102"
    assert ai_filter._declutter(line) == "IP Address: 10.128.18.102"
    iso = "2024-10-03T09:44:22.515Z [INFO] Entry EXE: Agent.exe"
    assert ai_filter._declutter(iso) == "Entry EXE: Agent.exe"
    plain = "password=hunter2hunter2!!"
    assert ai_filter._declutter(plain) == plain  # nothing to strip, unchanged


def test_declutter_never_returns_empty_for_a_timestamp_only_line():
    only_ts = "10-03-2024 09:44:22.515 [X]"
    assert ai_filter._declutter(only_ts).strip()


def test_marked_block_declutters_every_line():
    f = Finding(detector="Private IP (RFC1918)", severity=Severity.MEDIUM, line=2,
                redacted="1***", context="IP Address: 10.128.18.102", secret="10.128.18.102",
                context_block=[
                    [1, "10-03-2024 09:44:22.516 [X]    Computer: SCRUZ-L-344"],
                    [2, "10-03-2024 09:44:22.518 [X]    IP Address: 10.128.18.102"],
                    [3, "10-03-2024 09:44:22.519 [X]    Domain: disagrupo.es"],
                ])
    block = ai_filter._marked_block(f)
    assert "10-03-2024" not in block
    assert ">>> IP Address: 10.128.18.102" in block
    assert "Computer: SCRUZ-L-344" in block and "Domain: disagrupo.es" in block


def test_ipv6_and_phone_are_judged():
    from exhume.detectors import scan_text
    f_ip6 = next(f for f in scan_text("interfaz eth0 inet6 8::1/64", 3.5) if f.detector == "IPv6 address")
    assert ai_filter._is_judged(f_ip6)
    f_phone = next(f for f in scan_text("Móvil: 612345678", 3.5) if f.detector == "Phone number")
    assert ai_filter._is_judged(f_phone)
