"""Tests for scan configuration, in particular the --max-size "0 = no limit" semantics and
the --deep/--quick profiles, after a real scan reported unwanted skips (binary/media/too-big)
with no way to turn them off."""
from __future__ import annotations

from exhume.config import Config


def test_max_bytes_default():
    cfg = Config()
    assert cfg.max_bytes == 100 * 1024 * 1024


def test_max_size_zero_means_no_limit():
    """max_bytes must be None, not some huge sentinel int: file.read(N) for an oversized N can
    itself raise MemoryError trying to size a buffer up front, even for a small real file —
    found by actually running --deep against a 105MB file, which crashed with exactly that
    before this fix. Every caller must treat None as "no cap", not a number to compare against."""
    cfg = Config(max_size_mb=0)
    assert cfg.max_bytes is None


def test_deep_profile_lifts_the_size_cap_entirely():
    cfg = Config()  # default max_size_mb=100
    cfg.apply_profile(deep=True)
    assert cfg.max_size_mb == 0
    assert cfg.scan_strings is True
    assert cfg.ocr is True


def test_deep_profile_respects_an_explicit_larger_cap():
    cfg = Config(max_size_mb=500)
    cfg.apply_profile(deep=True)
    assert cfg.max_size_mb == 500


def test_quick_profile_overrides_unlimited_with_its_own_small_cap():
    """--quick --max-size 0 shouldn't accidentally stay "unlimited" just because min(0, 25) == 0."""
    cfg = Config(max_size_mb=0)
    cfg.apply_profile(quick=True)
    assert cfg.max_size_mb == 25


def test_quick_profile_keeps_a_smaller_explicit_cap():
    cfg = Config(max_size_mb=10)
    cfg.apply_profile(quick=True)
    assert cfg.max_size_mb == 10
