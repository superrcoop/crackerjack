"""Backward compatibility wrapper for Crackerjack mutation rules.

Delegates to `crackerjack.rules`.
"""

from __future__ import annotations

from crackerjack.rules import (
    add_numbers_and_dates as add_num_date,
    add_special_chars as add_char,
    case_variants as case_recovery,
    reverse_word,
    swap_chars,
)

__all__ = [
    "reverse_word",
    "add_num_date",
    "add_char",
    "swap_chars",
    "case_recovery",
]
