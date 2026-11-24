from exhume import ai_filter
from exhume.detectors import scan_text
from exhume.models import FileResult, Verified


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
    assert "10.1.1.5" in G.prompt or "10.1...1.5" in G.prompt or "10.1" in G.prompt
    assert "3.2.2.1" not in G.prompt          # hidden (AI-false) findings are not triaged
