"""Data models and evaluation structures for Crackerjack."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class CompositionFlags:
    """Flags indicating character categories in a candidate password."""
    has_lower: bool = False
    has_upper: bool = False
    has_digit: bool = False
    has_symbol: bool = False

    @property
    def character_pool_size(self) -> int:
        """Calculate the theoretical character pool size."""
        pool = 0
        if self.has_lower:
            pool += 26
        if self.has_upper:
            pool += 26
        if self.has_digit:
            pool += 10
        if self.has_symbol:
            pool += 33  # Standard ASCII punctuation & printable symbols
        return pool or 1

    def to_dict(self) -> dict[str, bool]:
        return {
            "has_lower": self.has_lower,
            "has_upper": self.has_upper,
            "has_digit": self.has_digit,
            "has_symbol": self.has_symbol,
        }


@dataclass(slots=True)
class NISTEvaluation:
    """NIST SP 800-63B password policy and entropy evaluation."""
    length: int
    raw_entropy_bits: float
    effective_entropy_bits: float
    passed_min_length: bool  # >= 8 characters
    meets_recommended_length: bool  # >= 15 characters
    has_repetitive_pattern: bool
    has_sequential_pattern: bool
    is_dictionary_word: bool
    composition: CompositionFlags
    score: int  # 0 to 100
    grade: str  # A+, A, B, C, D, F
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "length": self.length,
            "raw_entropy_bits": round(self.raw_entropy_bits, 2),
            "effective_entropy_bits": round(self.effective_entropy_bits, 2),
            "passed_min_length": self.passed_min_length,
            "meets_recommended_length": self.meets_recommended_length,
            "has_repetitive_pattern": self.has_repetitive_pattern,
            "has_sequential_pattern": self.has_sequential_pattern,
            "is_dictionary_word": self.is_dictionary_word,
            "composition": self.composition.to_dict(),
            "score": self.score,
            "grade": self.grade,
            "recommendations": self.recommendations,
        }


@dataclass(slots=True)
class BreachInfo:
    """HaveIBeenPwned k-anonymity breach check information."""
    pwned: bool = False
    breach_count: int = 0
    sha1_prefix: str = ""
    sha1_suffix: str = ""
    offline: bool = False
    status_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pwned": self.pwned,
            "breach_count": self.breach_count,
            "sha1_prefix": self.sha1_prefix,
            "offline": self.offline,
            "status_message": self.status_message,
        }


@dataclass(slots=True)
class PasswordHealthReport:
    """Consolidated password health, breach status, and NIST assessment."""
    password_masked: str
    nist: NISTEvaluation
    breach: BreachInfo
    verdict: str
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "password_masked": self.password_masked,
            "nist": self.nist.to_dict(),
            "breach": self.breach.to_dict(),
            "verdict": self.verdict,
            "summary": self.summary,
        }


@dataclass(slots=True)
class HashAuditResult:
    """Result of auditing a specific password hash."""
    target_hash: str
    cracked: bool
    plaintext: str | None
    hash_type: str
    attempts: int
    elapsed_seconds: float
    hash_rate: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_hash": self.target_hash,
            "cracked": self.cracked,
            "plaintext": self.plaintext,
            "hash_type": self.hash_type,
            "attempts": self.attempts,
            "elapsed_seconds": round(self.elapsed_seconds, 4),
            "hash_rate": round(self.hash_rate, 2),
        }


@dataclass(slots=True)
class BenchmarkResult:
    """Result of CPU core benchmark comparing single-core vs multi-core."""
    algorithm: str
    cost_factor: int
    workers: int
    single_core_rate: float
    multi_core_rate: float
    speedup: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "cost_factor": self.cost_factor,
            "workers": self.workers,
            "single_core_rate": round(self.single_core_rate, 2),
            "multi_core_rate": round(self.multi_core_rate, 2),
            "speedup": round(self.speedup, 2),
        }
