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


def test_ip_verifier_marks_open_port_valid_and_unreachable_public_invalid(monkeypatch):
    from exhume.models import Verified
    from exhume.verify import network
    monkeypatch.setattr(network, "_tcp_probe", lambda ip: "port 443 open" if ip == "1.1.1.1" else None)
    monkeypatch.setattr(network, "_ptr", lambda ip: None)
    assert network.verify_ip("1.1.1.1") == (Verified.VALID, "port 443 open")
    # A genuinely public, unreachable-from-here address: this IS the "looks like an IP but
    # isn't a real host" case the check exists to catch.
    status, _ = network.verify_ip("8.8.8.7")
    assert status is Verified.INVALID


def test_unreachable_private_ip_is_unknown_not_invalid(monkeypatch):
    """A private IP found in a log is real data even when this machine can't reach its network —
    failing to connect from outside proves nothing about whether the address itself is genuine."""
    from exhume.models import Verified
    from exhume.verify import network
    monkeypatch.setattr(network, "_tcp_probe", lambda ip: None)
    monkeypatch.setattr(network, "_ptr", lambda ip: None)
    status, detail = network.verify_ip("172.26.71.59")
    assert status is Verified.UNKNOWN
    assert "not reachable from this machine" in detail
    assert "does not mean it's fake" in detail


def test_unreachable_link_local_ip_is_unknown_not_invalid(monkeypatch):
    from exhume.models import Verified
    from exhume.verify import network
    monkeypatch.setattr(network, "_tcp_probe", lambda ip: None)
    monkeypatch.setattr(network, "_ptr", lambda ip: None)
    status, _ = network.verify_ip("169.254.1.1")
    assert status is Verified.UNKNOWN


def test_loopback_is_valid_without_probing(monkeypatch):
    """Probing 127.0.0.1 would test the SCANNING machine, not the target — never do that."""
    from exhume.models import Verified
    from exhume.verify import network

    def boom(ip):
        raise AssertionError("loopback must never be probed")

    monkeypatch.setattr(network, "_tcp_probe", boom)
    monkeypatch.setattr(network, "_ptr", boom)
    status, detail = network.verify_ip("127.0.0.1")
    assert status is Verified.VALID
    assert "scanning host" in detail


def test_reachable_private_ip_is_still_valid(monkeypatch):
    from exhume.models import Verified
    from exhume.verify import network
    monkeypatch.setattr(network, "_tcp_probe", lambda ip: "port 22 open")
    status, detail = network.verify_ip("10.0.0.5")
    assert status is Verified.VALID and "port 22 open" in detail
