"""Tests for mutation rules engine."""

from crackerjack.rules import (
    add_numbers_and_dates,
    add_special_chars,
    case_variants,
    mutate_word,
    reverse_word,
    swap_chars,
)


def test_reverse_word():
    assert reverse_word("password") == "drowssap"
    assert reverse_word("12345") == "54321"


def test_case_variants():
    variants = case_variants("apple")
    assert "apple" in variants
    assert "APPLE" in variants
    assert "Apple" in variants


def test_add_numbers_and_dates():
    results = add_numbers_and_dates("admin")
    assert "admin1" in results
    assert "admin123" in results
    assert "admin2024" in results


def test_add_special_chars():
    results = add_special_chars("secret")
    assert "secret!" in results
    assert "!secret" in results
    assert "secret@" in results


def test_swap_chars():
    swapped = swap_chars("pass")
    assert any("p@ss" in s or "pa$$" in s or "p@$$" in s for s in swapped)


def test_mutate_word_generator():
    generator = mutate_word("winter", max_variants=20)
    mutations = list(generator)
    assert len(mutations) > 5
    assert len(mutations) <= 20
    assert "winter" in mutations
    assert len(set(mutations)) == len(mutations)  # All unique
