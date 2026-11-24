"""Tests for entropy and Luhn."""
from __future__ import annotations

from exhume.detectors.entropy import luhn_valid, shannon_entropy


def test_entropy_bounds():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") > 1.9  # 4 equiprobable symbols => 2 bits


def test_entropy_random_higher_than_repetitive():
    assert shannon_entropy("aZ9kLmQ2wXy7bN4pR8tV") > shannon_entropy("aaaaaaaaaaaaaaaaaaaa")


def test_luhn():
    assert luhn_valid("4111111111111111")
    assert luhn_valid("5500005555555559")
    assert not luhn_valid("4111111111111112")
    assert not luhn_valid("1234")
