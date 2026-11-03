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
    has_context_words: bool = False
    matched_context_terms: list[str] = field(default_factory=list)
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
            "has_context_words": self.has_context_words,
            "matched_context_terms": self.matched_context_terms,
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


@dataclass(slots=True)
class TargetCredential:
    """A credential entry ingested from shadow files, NTDS, or CSV."""
    identity: str
    hash_val: str
    hash_type: str = "unknown"
    context_terms: list[str] = field(default_factory=list)
    cracked: bool = False
    plaintext: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "hash_val": self.hash_val,
            "hash_type": self.hash_type,
            "context_terms": self.context_terms,
            "cracked": self.cracked,
            "plaintext": self.plaintext,
        }


@dataclass(slots=True)
class GeneratedPassphrase:
    """NIST SP 800-63B compliant generated passphrase with certified entropy."""
    passphrase: str
    word_count: int
    separator: str
    entropy_bits: float
    effective_entropy_bits: float
    nist_score: int
    nist_grade: str
    breached: bool = False
    breach_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "passphrase": self.passphrase,
            "word_count": self.word_count,
            "separator": self.separator,
            "entropy_bits": round(self.entropy_bits, 2),
            "effective_entropy_bits": round(self.effective_entropy_bits, 2),
            "nist_score": self.nist_score,
            "nist_grade": self.nist_grade,
            "breached": self.breached,
            "breach_count": self.breach_count,
        }


@dataclass(slots=True)
class ComplianceSummary:
    """Enterprise compliance and security health aggregation."""
    total_evaluated: int
    total_cracked_or_weak: int
    total_breached: int
    avg_entropy: float
    overall_score: int
    overall_grade: str
    nist_compliant_pct: float
    pci_dss_compliant: bool
    grade_distribution: dict[str, int] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_evaluated": self.total_evaluated,
            "total_cracked_or_weak": self.total_cracked_or_weak,
            "total_breached": self.total_breached,
            "avg_entropy": round(self.avg_entropy, 2),
            "overall_score": self.overall_score,
            "overall_grade": self.overall_grade,
            "nist_compliant_pct": round(self.nist_compliant_pct, 1),
            "pci_dss_compliant": self.pci_dss_compliant,
            "grade_distribution": self.grade_distribution,
            "findings": self.findings,
        }


@dataclass(slots=True)
class ScanFinding:
    """Result of scanning a repository file for exposed credentials."""
    file_path: str
    line_number: int
    variable_name: str
    secret_masked: str
    raw_secret: str
    nist_score: int
    nist_grade: str
    breached: bool = False
    breach_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "variable_name": self.variable_name,
            "secret_masked": self.secret_masked,
            "nist_score": self.nist_score,
            "nist_grade": self.nist_grade,
            "breached": self.breached,
            "breach_count": self.breach_count,
        }

