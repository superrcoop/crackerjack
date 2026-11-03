"""Probabilistic & Context-Aware Password Mutation Engine."""

from __future__ import annotations

import datetime
from typing import Iterator

from crackerjack.rules import LEET_MAP


COMMON_SEASONS = ["Spring", "Summer", "Autumn", "Fall", "Winter"]
COMMON_SYMBOLS = ["!", "@", "#", "$", "%", "?", "*", "."]
COMMON_DIGIT_SUFFIXES = ["1", "12", "123", "1234", "01", "24", "25", "26", "2024", "2025", "2026"]


def _apply_leetspeak(word: str) -> list[str]:
    """Generate high-frequency leetspeak variations for a token."""
    variants = [word]
    # Simple substitution
    chars = list(word.lower())
    mutated = []
    has_sub = False
    for c in chars:
        if c in LEET_MAP:
            mutated.append(LEET_MAP[c][0])
            has_sub = True
        else:
            mutated.append(c)
    if has_sub:
        variants.append("".join(mutated))
    return variants


def generate_probabilistic_candidates(
    base_words: list[str],
    context_terms: list[str] | None = None,
    max_candidates: int = 2000,
) -> Iterator[str]:
    """Yield high-probability password candidates matching human cognitive habits.
    
    Combines organization tokens, names, calendar years, seasons, and common
    structural topologies (Word+Year+Symbol, Leet+Number, etc.).
    """
    seen: set[str] = set()
    yielded = 0

    current_year = datetime.datetime.now().year
    years = [str(current_year - 1), str(current_year), str(current_year + 1)]

    # Pool of core root tokens
    tokens: list[str] = []
    if context_terms:
        for ct in context_terms:
            clean = ct.strip()
            if clean and len(clean) >= 2:
                tokens.append(clean)

    for bw in base_words:
        clean = bw.strip()
        if clean and clean not in tokens:
            tokens.append(clean)

    # If empty, provide standard fallback roots
    if not tokens:
        tokens = ["Password", "Admin", "Welcome", "Company"]

    # Expansion Stages by Probability Rank

    # Stage 1: Exact and Capitalized Roots
    for token in tokens:
        for form in [token, token.capitalize(), token.lower(), token.upper()]:
            if form not in seen:
                seen.add(form)
                yield form
                yielded += 1
                if yielded >= max_candidates:
                    return

    # Stage 2: Token + Year / Common Suffix (e.g. Acme2026, Admin123)
    for token in tokens:
        cap = token.capitalize()
        for suffix in years + COMMON_DIGIT_SUFFIXES:
            cand = f"{cap}{suffix}"
            if cand not in seen:
                seen.add(cand)
                yield cand
                yielded += 1
                if yielded >= max_candidates:
                    return

    # Stage 3: Token + Year + Symbol (e.g. Acme2026!, Welcome123#)
    for token in tokens:
        cap = token.capitalize()
        for suffix in years + ["123", "1"]:
            for sym in COMMON_SYMBOLS:
                cand = f"{cap}{suffix}{sym}"
                if cand not in seen:
                    seen.add(cand)
                    yield cand
                    yielded += 1
                    if yielded >= max_candidates:
                        return

    # Stage 4: Token + Symbol + Year (e.g. Acme@2026)
    for token in tokens:
        cap = token.capitalize()
        for sym in ["@", "!", "#", "$"]:
            for y in years:
                cand = f"{cap}{sym}{y}"
                if cand not in seen:
                    seen.add(cand)
                    yield cand
                    yielded += 1
                    if yielded >= max_candidates:
                        return

    # Stage 5: Season + Year + Symbol (e.g. Spring2026!)
    for season in COMMON_SEASONS:
        for y in years:
            for sym in ["!", "@", "#", "1", "123"]:
                cand = f"{season}{y}{sym}"
                if cand not in seen:
                    seen.add(cand)
                    yield cand
                    yielded += 1
                    if yielded >= max_candidates:
                        return

    # Stage 6: Leetspeak mutations
    for token in tokens:
        for leet_form in _apply_leetspeak(token):
            for suffix in ["123", "!", "1", "2026"]:
                cand = f"{leet_form}{suffix}"
                if cand not in seen:
                    seen.add(cand)
                    yield cand
                    yielded += 1
                    if yielded >= max_candidates:
                        return
