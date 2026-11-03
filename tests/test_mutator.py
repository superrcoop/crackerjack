"""Unit tests for probabilistic and context-aware password mutation engine."""

from crackerjack.mutator import generate_probabilistic_candidates


def test_generate_probabilistic_candidates_basic():
    base_words = ["Acme", "Security"]
    candidates = list(generate_probabilistic_candidates(base_words, max_candidates=100))

    assert len(candidates) > 20
    assert "Acme" in candidates
    assert "Security" in candidates
    # Check that common years are appended
    assert any("2026" in c for c in candidates)
    # Check that symbols are appended
    assert any("!" in c or "@" in c for c in candidates)


def test_generate_probabilistic_with_context():
    context = ["finance", "london"]
    candidates = list(generate_probabilistic_candidates(base_words=["Corp"], context_terms=context, max_candidates=250))

    # Should prioritize context terms
    assert "Finance" in candidates or "finance" in candidates
    assert "London" in candidates or "london" in candidates
    # Check combination topologies (e.g. Finance2026!)
    assert any("Finance" in c and "2026" in c for c in candidates)
    assert any("London" in c for c in candidates)


def test_generate_candidates_limit():
    candidates = list(generate_probabilistic_candidates(["Test"], max_candidates=15))
    assert len(candidates) == 15
