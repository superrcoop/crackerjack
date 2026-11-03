"""Tests for NIST SP 800-63B passphrase generator."""

from pathlib import Path

from crackerjack.generator import generate_passphrase, load_wordlist


def test_load_default_wordlist():
    words = load_wordlist()
    assert len(words) > 300
    assert "battery" in words
    assert "staple" in words


def test_load_custom_wordlist(tmp_path: Path):
    custom_file = tmp_path / "custom_dict.txt"
    custom_content = "\n".join([f"wordentry{i}" for i in range(150)])
    custom_file.write_text(custom_content, encoding="utf-8")

    words = load_wordlist(custom_file)
    assert len(words) == 150
    assert "wordentry0" in words


def test_generate_passphrase_basic():
    res = generate_passphrase(
        word_count=4,
        separator="-",
        capitalize=False,
        add_number=False,
        add_symbol=False,
        check_breach=False,
    )

    parts = res.passphrase.split("-")
    assert len(parts) == 4
    assert res.word_count == 4
    assert res.entropy_bits > 40.0
    assert res.nist_score >= 80
    assert res.nist_grade in ("A+", "A")
    assert res.breached is False


def test_generate_passphrase_with_number_and_symbol():
    res = generate_passphrase(
        word_count=5,
        separator="_",
        capitalize=True,
        add_number=True,
        add_symbol=True,
        check_breach=False,
    )

    assert "_" in res.passphrase
    # First letter of first word should be uppercase
    assert res.passphrase[0].isupper()
    # Higher entropy due to 5 words + numbers + symbol
    assert res.entropy_bits > 60.0
    assert res.nist_grade in ("A+", "A")
