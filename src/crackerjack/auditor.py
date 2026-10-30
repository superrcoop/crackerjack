"""NIST SP 800-63B Password Policy and Health Auditor.

Implements guidelines from NIST Special Publication 800-63B Section 5.1.1.2:
- Minimum length enforcement (>= 8 chars required, >= 15 recommended).
- Elimination of counter-productive arbitrary composition rules.
- Resistance to dictionary words, repetition, and keyboard/sequential walks.
- Shannon and theoretical entropy modeling.
"""

from __future__ import annotations

import math
import re
import string
from collections import Counter

from crackerjack.models import CompositionFlags, NISTEvaluation

# Common sequential keyboard walks and character sequences
COMMON_SEQUENCES: list[str] = [
    "01234567890",
    "9876543210",
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1qaz2wsx3edc",
]

# High-frequency dictionary roots and top weak passwords
COMMON_WEAK_ROOTS: set[str] = {
    "password", "admin", "welcome", "login", "master", "monkey",
    "dragon", "baseball", "football", "shadow", "sunshine", "princess",
    "superman", "starwars", "secret", "default", "root", "test", "guest",
    "letmein", "trustno1", "access", "qwerty", "iloveyou", "computer"
}

LEET_REPLACEMENTS: dict[str, str] = {
    "@": "a", "4": "a",
    "8": "b",
    "3": "e",
    "1": "i", "!": "i",
    "0": "o",
    "$": "s", "5": "s",
    "7": "t", "+": "t",
}


def normalize_leetspeak(text: str) -> str:
    """Normalize common leetspeak substitutions back to Latin characters."""
    chars = [LEET_REPLACEMENTS.get(c, c) for c in text.lower()]
    return "".join(chars)


def detect_composition(password: str) -> CompositionFlags:
    """Detect presence of character categories."""
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_symbol = any(c in string.punctuation or (not c.isalnum() and not c.isspace()) for c in password)
    return CompositionFlags(
        has_lower=has_lower,
        has_upper=has_upper,
        has_digit=has_digit,
        has_symbol=has_symbol,
    )


def detect_repetition(password: str) -> bool:
    """Detect 3 or more consecutive identical characters (e.g. 'aaa', '111')."""
    return bool(re.search(r"(.)\1{2,}", password))


def detect_sequential_patterns(password: str, min_len: int = 3) -> bool:
    """Detect keyboard walks or alphabet/number sequences of min_len or greater."""
    lowered = password.lower()
    for seq in COMMON_SEQUENCES:
        for i in range(len(seq) - min_len + 1):
            sub = seq[i : i + min_len]
            if sub in lowered:
                return True
    return False


def detect_dictionary_root(password: str) -> bool:
    """Check if password contains a common weak root word (even with leetspeak)."""
    normalized = normalize_leetspeak(password)
    # Strip digits and punctuation from ends
    trimmed = re.sub(r"^[0-9!@#\$%\^&*\-_+]+|[0-9!@#\$%\^&*\-_+]+$", "", normalized)
    if trimmed in COMMON_WEAK_ROOTS:
        return True
    for root in COMMON_WEAK_ROOTS:
        if len(root) >= 4 and root in normalized:
            return True
    return False


def detect_context_words(password: str, context_terms: list[str] | None = None) -> list[str]:
    """Check if password contains any context-specific terms (usernames, company, service).

    Per NIST SP 800-63B Section 5.1.1.2: prospective secrets must be compared against
    values provided by the applicant (e.g. username, company name, service name).
    """
    if not context_terms:
        return []

    lowered = password.lower()
    normalized = normalize_leetspeak(password)
    matches: list[str] = []

    for term in context_terms:
        clean_term = term.strip().lower()
        if len(clean_term) < 3:
            continue
        # Direct substring match
        if clean_term in lowered:
            matches.append(term)
            continue
        # Leetspeak match
        if clean_term in normalized:
            matches.append(term)
            continue
        # Reverse match
        if clean_term[::-1] in lowered or clean_term[::-1] in normalized:
            matches.append(term)
            continue

    return list(dict.fromkeys(matches))  # Preserve unique order


def calculate_entropy(password: str, composition: CompositionFlags) -> tuple[float, float]:
    """Calculate raw entropy and penalized effective entropy in bits."""
    length = len(password)
    if length == 0:
        return 0.0, 0.0

    pool_size = composition.character_pool_size
    raw_entropy = length * math.log2(pool_size)

    # Shannon character-frequency entropy
    freqs = Counter(password)
    shannon_entropy_per_char = -sum(
        (count / length) * math.log2(count / length) for count in freqs.values()
    )
    shannon_total = shannon_entropy_per_char * length

    # Start effective entropy from lower of pool entropy and Shannon total
    effective = min(raw_entropy, shannon_total * (math.log2(pool_size) / max(shannon_entropy_per_char, 1e-6)))
    effective = min(effective, raw_entropy)

    # Penalties for structural weaknesses
    if detect_repetition(password):
        effective *= 0.70
    if detect_sequential_patterns(password):
        effective *= 0.75
    if detect_dictionary_root(password):
        effective *= 0.60

    return max(0.0, raw_entropy), max(0.0, effective)


def evaluate_password(password: str, context_terms: list[str] | None = None) -> NISTEvaluation:
    """Perform a full NIST SP 800-63B evaluation of a plaintext password.

    Args:
        password: The plaintext candidate password.
        context_terms: Optional list of context words (username, service name, organization).
    """
    length = len(password)
    composition = detect_composition(password)
    passed_min_length = length >= 8
    meets_recommended_length = length >= 15
    has_repetitive = detect_repetition(password)
    has_sequential = detect_sequential_patterns(password)
    is_dictionary = detect_dictionary_root(password)
    matched_context = detect_context_words(password, context_terms)
    has_context = bool(matched_context)

    raw_entropy, effective_entropy = calculate_entropy(password, composition)
    if has_context:
        effective_entropy *= 0.60

    recommendations: list[str] = []

    # Score calculation (0 to 100)
    score = 0

    if not passed_min_length:
        score = min(30, int(length * 3.5))
        recommendations.append("NIST SP 800-63B requires a minimum length of at least 8 characters.")
    else:
        # Base score from effective entropy (up to 70 points for 70+ bits)
        score += min(70, int(effective_entropy * 0.9))

        # Length bonus (up to 20 points)
        if meets_recommended_length:
            score += 20
        elif length >= 12:
            score += 12
        else:
            score += 5

        # Diversity contribution (up to 10 points)
        categories = sum([
            composition.has_lower,
            composition.has_upper,
            composition.has_digit,
            composition.has_symbol,
        ])
        score += min(10, categories * 2.5)

    # Penalties applied to score
    if has_repetitive:
        score -= 15
        recommendations.append("Avoid consecutive repeating characters (e.g., 'aaa', '111').")
    if has_sequential:
        score -= 15
        recommendations.append("Avoid sequential keyboard or alphabetical walks (e.g., '12345', 'qwerty').")
    if is_dictionary:
        score -= 25
        recommendations.append("Avoid common dictionary roots and easily guessable terms (even with leetspeak substitutions).")
    if has_context:
        score -= 30
        recommendations.append(
            f"Avoid context-specific terms ({', '.join(matched_context)}). "
            f"NIST SP 800-63B requires rejecting words associated with the applicant, service, or organization."
        )

    if not meets_recommended_length and passed_min_length:
        recommendations.append("Consider increasing length to 15+ characters (e.g. a multi-word passphrase).")

    score = max(0, min(100, int(score)))

    # Grade assignment
    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    if not recommendations:
        recommendations.append("Excellent password health! Meets and exceeds NIST SP 800-63B recommendations.")

    return NISTEvaluation(
        length=length,
        raw_entropy_bits=raw_entropy,
        effective_entropy_bits=effective_entropy,
        passed_min_length=passed_min_length,
        meets_recommended_length=meets_recommended_length,
        has_repetitive_pattern=has_repetitive,
        has_sequential_pattern=has_sequential,
        is_dictionary_word=is_dictionary,
        has_context_words=has_context,
        matched_context_terms=matched_context,
        composition=composition,
        score=score,
        grade=grade,
        recommendations=recommendations,
    )
