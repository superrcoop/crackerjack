"""Password mutation rules engine for hybrid dictionary auditing.

Modernizes and completes the rules originally stubbed in Crackerjack:
- Reverse word
- Number and date additions
- Special character insertions
- Leetspeak character swaps
- Case recoveries and permutations
"""

from __future__ import annotations

import itertools
from typing import Iterator

LEET_MAP: dict[str, list[str]] = {
    "a": ["@", "4"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["$", "5"],
    "t": ["7", "+"],
    "b": ["8"],
    "g": ["9"],
}

COMMON_SUFFIX_NUMS: list[str] = [
    "1", "12", "123", "1234", "01", "07", "99",
    "2020", "2021", "2022", "2023", "2024", "2025", "2026",
    "1990", "1995", "2000", "007"
]

COMMON_SPECIAL_CHARS: list[str] = [
    "!", "?", "@", "#", "$", "%", "*", "_", "-", "!!", "!1"
]


def reverse_word(word: str) -> str:
    """Reverse the characters of a word (e.g. 'password' -> 'drowssap')."""
    return word[::-1]


def case_variants(word: str) -> list[str]:
    """Generate case variations: original, lower, upper, title, inverted."""
    variants = {
        word,
        word.lower(),
        word.upper(),
        word.capitalize(),
        word.swapcase(),
    }
    return list(variants)


def add_numbers_and_dates(word: str) -> list[str]:
    """Append common numbers and year dates to the word."""
    results = []
    for num in COMMON_SUFFIX_NUMS:
        results.append(f"{word}{num}")
    return results


def add_special_chars(word: str) -> list[str]:
    """Append and prepend common special symbols."""
    results = []
    for sym in COMMON_SPECIAL_CHARS:
        results.append(f"{word}{sym}")
        results.append(f"{sym}{word}")
    return results


def swap_chars(word: str, max_variations: int = 16) -> list[str]:
    """Generate leetspeak character substitutions (e.g. 'password' -> 'p@ssw0rd')."""
    indices_with_replacements: list[tuple[int, list[str]]] = []
    for idx, ch in enumerate(word.lower()):
        if ch in LEET_MAP:
            options = [word[idx]] + LEET_MAP[ch]
            indices_with_replacements.append((idx, options))

    if not indices_with_replacements:
        return [word]

    # Limit combinations to prevent combinatorial blowup
    chosen_replacements = indices_with_replacements[:4]
    indices = [x[0] for x in chosen_replacements]
    option_lists = [x[1] for x in chosen_replacements]

    generated: set[str] = set()
    for product in itertools.product(*option_lists):
        chars = list(word)
        for idx, repl in zip(indices, product):
            chars[idx] = repl
        generated.add("".join(chars))
        if len(generated) >= max_variations:
            break

    return list(generated)


def mutate_word(word: str, max_variants: int = 40) -> Iterator[str]:
    """Stream intelligent rule-based mutations for a given dictionary word.

    Yields original first, then case variations, leetspeak, and symbol/number combos.
    """
    seen: set[str] = set()

    # 1. Base case variants
    for var in case_variants(word):
        if var not in seen:
            seen.add(var)
            yield var

    # 2. Leet variants
    for leet in swap_chars(word, max_variations=8):
        if leet not in seen:
            seen.add(leet)
            yield leet
            if len(seen) >= max_variants:
                return

    # 3. Number suffixes on original and title
    for base in [word, word.capitalize()]:
        for num in COMMON_SUFFIX_NUMS[:6]:
            combined = f"{base}{num}"
            if combined not in seen:
                seen.add(combined)
                yield combined
                if len(seen) >= max_variants:
                    return

    # 4. Special symbol additions
    for base in [word, word.capitalize()]:
        for sym in COMMON_SPECIAL_CHARS[:4]:
            combined = f"{base}{sym}"
            if combined not in seen:
                seen.add(combined)
                yield combined
                if len(seen) >= max_variants:
                    return

    # 5. Reverse word
    rev = reverse_word(word)
    if rev not in seen:
        seen.add(rev)
        yield rev
