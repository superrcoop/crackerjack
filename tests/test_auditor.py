"""Tests for NIST SP 800-63B policy auditor and entropy calculator."""

from crackerjack.auditor import (
    calculate_entropy,
    detect_composition,
    detect_dictionary_root,
    detect_repetition,
    detect_sequential_patterns,
    evaluate_password,
    normalize_leetspeak,
)


def test_composition_detection():
    comp = detect_composition("Abc12#")
    assert comp.has_lower is True
    assert comp.has_upper is True
    assert comp.has_digit is True
    assert comp.has_symbol is True
    assert comp.character_pool_size == 26 + 26 + 10 + 33

    comp_simple = detect_composition("secret")
    assert comp_simple.has_lower is True
    assert comp_simple.has_upper is False
    assert comp_simple.character_pool_size == 26


def test_repetition_detection():
    assert detect_repetition("aaaa") is True
    assert detect_repetition("pass111word") is True
    assert detect_repetition("securepass") is False


def test_sequential_detection():
    assert detect_sequential_patterns("pass123word") is True
    assert detect_sequential_patterns("myqwertytest") is True
    assert detect_sequential_patterns("abc999") is True
    assert detect_sequential_patterns("k9#Xm!2$") is False


def test_leetspeak_and_dictionary_detection():
    assert normalize_leetspeak("p@ssw0rd") == "password"
    assert detect_dictionary_root("p@ssw0rd123") is True
    assert detect_dictionary_root("Admin2024!") is True
    assert detect_dictionary_root("X#9qL!mPz8v$") is False


def test_nist_short_password_fails():
    eval_short = evaluate_password("short")
    assert eval_short.passed_min_length is False
    assert eval_short.grade == "F"
    assert any("minimum length" in rec for rec in eval_short.recommendations)


def test_nist_strong_passphrase():
    passphrase = "correct-horse-battery-staple-2026"
    eval_strong = evaluate_password(passphrase)
    assert eval_strong.passed_min_length is True
    assert eval_strong.meets_recommended_length is True
    assert eval_strong.effective_entropy_bits > 70.0
    assert eval_strong.grade in ("A", "A+")
    assert eval_strong.score >= 85


def test_entropy_penalties():
    comp = detect_composition("12345678")
    raw, eff = calculate_entropy("12345678", comp)
    # Sequential pattern penalty should reduce effective entropy
    assert eff < raw


def test_detect_context_words():
    from crackerjack.auditor import detect_context_words

    context = ["acme", "johndoe", "github"]

    # Direct match
    assert "acme" in detect_context_words("Welcome2AcmeCorp!", context)
    assert "johndoe" in detect_context_words("johndoe2026", context)

    # Leetspeak match (@ for a, 3 for e)
    assert "acme" in detect_context_words("@cm3_secure_pass", context)

    # Reverse match
    assert "acme" in detect_context_words("emca_pass_2026", context)

    # Unrelated
    assert detect_context_words("completely_unrelated_passphrase", context) == []


def test_nist_evaluation_with_context_penalty():
    # Passphrase that would otherwise be strong, but contains the applicant's company name
    eval_no_context = evaluate_password("AcmeCorporationSecure#2026!")
    eval_with_context = evaluate_password("AcmeCorporationSecure#2026!", context_terms=["acme"])

    assert eval_with_context.has_context_words is True
    assert "acme" in eval_with_context.matched_context_terms
    assert eval_with_context.score < eval_no_context.score
    assert any("context-specific" in rec for rec in eval_with_context.recommendations)
