"""Tests for network validation (real IPs/URLs) and focused context."""
from __future__ import annotations

import pytest

from exhume.detectors import scan_text
from exhume.detectors.validators import (
    is_ipv4_private,
    is_ipv4_public,
    is_ipv6,
    is_url_public,
)


@pytest.mark.parametrize("value,expected", [
    ("192.168.1.10", True), ("10.0.0.1", True), ("172.16.5.4", True),
    ("127.0.0.1", True), ("8.8.8.8", False), ("999.1.2.3", False),
    ("1.2.3.4.5", False),
])
def test_ipv4_private(value, expected):
    assert is_ipv4_private(value) is expected


@pytest.mark.parametrize("value,expected", [
    ("8.8.8.8", True), ("1.1.1.1", True), ("192.168.1.1", False),
    ("10.0.0.1", False), ("256.1.1.1", False),
])
def test_ipv4_public(value, expected):
    assert is_ipv4_public(value) is expected


@pytest.mark.parametrize("value,expected", [
    ("2001:db8::1", True), ("::1", True),
    ("12:34:56", False), ("notanip", False), ("::", False),
])
def test_ipv6(value, expected):
    assert is_ipv6(value) is expected


@pytest.mark.parametrize("value,expected", [
    ("https://example.com/x", True), ("http://8.8.8.8/", True),
    ("https://panel.corp/login", False), ("https://localhost/x", False),
    ("http://10.0.0.1/", False), ("notaurl", False),
])
def test_url_public(value, expected):
    assert is_url_public(value) is expected


def test_version_string_not_detected_as_ip():
    dets = {f.detector for f in scan_text("app version 1.2.3.4.5 released", 3.8)}
    assert "Private IP (RFC1918)" not in dets
    assert "Public IPv4" not in dets


def test_invalid_octet_not_detected():
    dets = {f.detector for f in scan_text("rango 300.400.500.600 roto", 3.8)}
    assert not any("IP" in d for d in dets)


def test_focused_context_window():
    huge = "x" * 3000 + " token=AKIAIOSFODNN7EXAMPLE " + "y" * 3000
    f = next(x for x in scan_text(huge, 3.8, context_width=40) if x.detector == "AWS Access Key ID")
    # The context is a small window, not the whole line
    assert len(f.context) < 200
    assert f.context.startswith("…") and f.context.endswith("…")
    # Context is stored RAW (report shows real values by default); masking is report-time.
    assert "AKIAIOSFODNN7EXAMPLE" in f.context
    assert "AKIAIOSFODNN7EXAMPLE" not in f.to_public_dict()["context"]  # masked view


def test_dedupe_overlapping_detectors():
    # A public IP must not also count as private (mutually-exclusive validators)
    findings = scan_text("8.8.8.8", 3.8)
    ip_findings = [f for f in findings if f.detector in ("Private IP (RFC1918)", "Public IPv4")]
    assert len(ip_findings) == 1
    assert ip_findings[0].detector == "Public IPv4"
