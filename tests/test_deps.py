"""Tests for optional-dependency auto-install, especially the pipx/uv "no pip in the venv" case."""
from __future__ import annotations

from exhume import deps


def _reset_cache(monkeypatch):
    monkeypatch.setattr(deps, "_pip_ready", None, raising=False)


def test_ensure_pip_skips_bootstrap_when_pip_already_works(monkeypatch):
    _reset_cache(monkeypatch)
    calls = []
    monkeypatch.setattr(deps, "_pip_available", lambda: True)

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        raise AssertionError("ensurepip should not run when pip already works")

    monkeypatch.setattr(deps.subprocess, "run", fake_run)
    assert deps.ensure_pip() is True
    assert calls == []


def test_ensure_pip_bootstraps_via_ensurepip_when_pip_is_missing(monkeypatch):
    """Simulates a pipx/uv-managed venv: pip is stripped after install, but ensurepip (stdlib)
    can rebuild it — this is exactly what makes a globally-installed Exhume self-sufficient."""
    _reset_cache(monkeypatch)
    state = {"pip_present": False}

    def fake_run(cmd, **kwargs):
        class R:
            returncode = 0
        if cmd[1:3] == ["-m", "ensurepip"]:
            state["pip_present"] = True
        return R()

    monkeypatch.setattr(deps.subprocess, "run", fake_run)
    monkeypatch.setattr(deps, "_pip_available", lambda: state["pip_present"])
    assert deps.ensure_pip() is True
    assert state["pip_present"] is True


def test_ensure_pip_returns_false_when_ensurepip_also_fails(monkeypatch):
    _reset_cache(monkeypatch)
    monkeypatch.setattr(deps, "_pip_available", lambda: False)
    monkeypatch.setattr(deps.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError("nope")))
    assert deps.ensure_pip() is False


def test_pip_install_gives_up_early_without_bootstrapping_pip(monkeypatch):
    """If pip can never be made to work, don't even try `pip install` (it would just fail N times)."""
    _reset_cache(monkeypatch)
    monkeypatch.setattr(deps, "ensure_pip", lambda: False)
    calls = []
    monkeypatch.setattr(deps.subprocess, "run", lambda *a, **k: calls.append(a))
    assert deps.pip_install("somepkg") is False
    assert calls == []
