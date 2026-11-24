"""Tests for the secret and PII detectors."""
from __future__ import annotations

import pytest

from exhume.detectors import scan_text
from exhume.models import Severity


def _detectors(text):
    return {f.detector for f in scan_text(text, min_entropy=3.8)}


# NOTE: the sample tokens below are split with "+" so the full provider-format
# literal never appears in the source file. They are reassembled at runtime, so
# Exhume still detects them, but GitHub push protection (and other scanners) do
# not flag this test file. These are fake values — none is a real credential.
@pytest.mark.parametrize("text,expected", [
    ("AKIA" + "IOSFODNN7EXAMPLE", "AWS Access Key ID"),
    ("AIza" + "SyA1234567890abcdefghijklmnopqrstuv", "Google API key"),
    ("ghp_" + "1234567890abcdefABCDEF1234567890abcd", "GitHub token"),
    ("glpat-" + "abcdef1234567890ABCD", "GitLab token"),
    ("xoxb-" + "123456789012-ABCDEFGHIJKLMNOP", "Slack token"),
    ("sk_" + "live_abcdef0123456789abcdef01", "Stripe secret key"),
    ("dop_v1_" + "a" * 64, "DigitalOcean token"),
    ("sk-" + "ant-api03-ABCDEFGHIJKLMNOPQRSTUV", "Anthropic API key"),
    ('{"type": "service_account"}', "GCP service account (JSON)"),
    ("-----BEGIN RSA PRIVATE KEY-----", "Private key (PEM)"),
    ("postgres://user:pass@10.0.0.1:5432/db", "Connection URI with credentials"),
    ("123456789" + ":AABBccddeeffGGhhIIjjKKllMMnnOOppQQ11", "Telegram bot token"),
])
def test_detects(text, expected):
    assert expected in _detectors(text)


def test_credit_card_luhn():
    assert "Credit card" in _detectors("4111111111111111")       # valid
    assert "Credit card" not in _detectors("4111111111111112")   # Luhn fails


def test_email_and_pii():
    found = _detectors("contact: john@company.com  DNI 12345678Z")
    assert "Email" in found
    assert "Spanish DNI/NIF" in found


def test_placeholder_not_flagged():
    findings = scan_text("password=changeme", min_entropy=3.8)
    vals = [f.redacted for f in findings if f.detector == "Credential assignment"]
    assert vals == []


def _has_pw(text):
    return any(f.detector == "Credential assignment" for f in scan_text(text, 3.8))


@pytest.mark.parametrize("text", [
    "password = req.body.password",
    "password = getEnv('DB_PASS')",
    "const password = user.password;",
    "password: string;",
    "password = None",
    "password = ${DB_PASSWORD}",
    "bypass=true",
    "compass=magnetic",
])
def test_code_reference_false_positives_ignored(text):
    assert not _has_pw(text)


@pytest.mark.parametrize("text", [
    'password = "Hunter2Winter!"',
    "DB_PASSWORD=S3cr3t_P@ss_2024_xyz",
    "MYSQL_PASSWORD=Xkcd_Horse_99_Battery",
])
def test_real_passwords_detected(text):
    assert _has_pw(text)


def test_multiline_context_block():
    text = "line1\nline2\nAPI_KEY=AKIAIOSFODNN7EXAMPLE\nline4\nline5"
    f = next(x for x in scan_text(text, 3.8) if x.detector == "AWS Access Key ID")
    lines = {n for n, _ in f.context_block}
    assert f.line in lines
    assert len(f.context_block) >= 3  # surrounding lines captured
    assert f.col > 0


def test_high_entropy_generic():
    text = "token = 'aZ9kLmQ2wXy7bN4pR8tV6cD1eF3gH5jK0'"
    found = _detectors(text)
    assert any("entropy" in d or "Credential" in d for d in found)


def test_severity_ordering():
    findings = scan_text("AKIAIOSFODNN7EXAMPLE\njohn@x.com", min_entropy=3.8)
    aws = next(f for f in findings if f.detector == "AWS Access Key ID")
    email = next(f for f in findings if f.detector == "Email")
    assert aws.severity == Severity.CRITICAL
    assert email.severity == Severity.MEDIUM
    assert aws.severity > email.severity


def test_secret_captured_but_not_in_public_dict():
    f = scan_text("ghp_" + "1234567890abcdefABCDEF1234567890abcd", 3.8)[0]
    assert f.secret is not None
    assert "secret" not in f.to_public_dict()
