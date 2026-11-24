"""Tests for active verification (HTTP mocked, no real network)."""
from __future__ import annotations

from exhume.models import Verified
from exhume.verify import verifiers


def test_github_live(monkeypatch):
    monkeypatch.setattr(verifiers, "_http", lambda *a, **k: (200, '{"login": "alice"}'))
    status, detail = verifiers.verify_single("github", "ghp_x")
    assert status is Verified.LIVE
    assert "alice" in detail


def test_github_dead(monkeypatch):
    monkeypatch.setattr(verifiers, "_http", lambda *a, **k: (401, "{}"))
    status, _ = verifiers.verify_single("github", "ghp_x")
    assert status is Verified.DEAD


def test_network_error_unknown(monkeypatch):
    monkeypatch.setattr(verifiers, "_http", lambda *a, **k: (None, "neterr:Timeout"))
    status, _ = verifiers.verify_single("stripe", "sk_live_x")
    assert status is Verified.UNKNOWN


def test_slack_ok_false_is_dead(monkeypatch):
    monkeypatch.setattr(verifiers, "_http", lambda *a, **k: (200, '{"ok": false, "error": "invalid_auth"}'))
    status, detail = verifiers.verify_single("slack", "xoxb-x")
    assert status is Verified.DEAD
    assert "invalid_auth" in detail


def test_unknown_verifier_key():
    status, detail = verifiers.verify_single("no-existe", "x")
    assert status is Verified.UNKNOWN


def test_aws_sigv4_live(monkeypatch):
    resp = "<Account>123456789012</Account><Arn>arn:aws:iam::1:user/bob</Arn>"
    monkeypatch.setattr(verifiers, "_http", lambda *a, **k: (200, resp))
    status, detail = verifiers.verify_aws_pair("AKIA" + "A" * 16, "s" * 40)
    assert status is Verified.LIVE
    assert "123456789012" in detail


def test_aws_sigv4_dead(monkeypatch):
    monkeypatch.setattr(verifiers, "_http", lambda *a, **k: (403, "forbidden"))
    status, _ = verifiers.verify_aws_pair("AKIA" + "A" * 16, "s" * 40)
    assert status is Verified.DEAD


def test_ip_verifier_marks_open_port_valid_and_unreachable_invalid(monkeypatch):
    from exhume.models import Verified
    from exhume.verify import network
    monkeypatch.setattr(network, "_tcp_probe", lambda ip: "port 443 open" if ip == "1.1.1.1" else None)
    monkeypatch.setattr(network, "_ptr", lambda ip: None)
    assert network.verify_ip("1.1.1.1") == (Verified.VALID, "port 443 open")
    status, _ = network.verify_ip("203.0.113.9")
    assert status is Verified.INVALID
