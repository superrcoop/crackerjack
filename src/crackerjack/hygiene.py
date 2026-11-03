"""Cryptographic Posture & Modern KDF Migration Assessment."""

from __future__ import annotations

from collections import Counter
from typing import Sequence

from crackerjack.engine import detect_hash_type
from crackerjack.models import CryptoHygieneFinding, CryptoHygieneReport, TargetCredential


def _evaluate_algorithm_hygiene(algo: str, sample_hash: str = "") -> tuple[str, str, str, str, str]:
    """Return (status, risk_level, gpu_cracking_speed, pqc_readiness, recommendation)."""
    norm = algo.lower()

    if norm in ("ntlm", "lm"):
        return (
            "deprecated",
            "CRITICAL",
            "~320 Billion H/s (8x RTX 4090)",
            "VULNERABLE (Cracked instantaneously on commodity GPUs)",
            "Disable NTLM/LM authentication immediately in Active Directory; enforce Kerberos with AES-256.",
        )
    elif norm in ("md5", "md5crypt"):
        return (
            "deprecated",
            "CRITICAL",
            "~180 Billion H/s (8x RTX 4090)",
            "VULNERABLE (Collision-prone; trivial brute force)",
            "Cease usage immediately. Migrate all active user hashes to Argon2id.",
        )
    elif norm in ("sha1", "sha1crypt"):
        return (
            "deprecated",
            "CRITICAL",
            "~45 Billion H/s (8x RTX 4090)",
            "VULNERABLE (Cryptographically broken against chosen-prefix attacks)",
            "Migrate immediately to memory-hard KDFs (Argon2id or Bcrypt rounds >= 12).",
        )
    elif norm == "sha512crypt":
        return (
            "weak",
            "HIGH",
            "~250 Million H/s (8x RTX 4090)",
            "WEAK (Lacks memory-hardness; highly susceptible to GPU clusters)",
            "Upgrade Linux shadow configuration (/etc/login.defs) to yescrypt or Argon2.",
        )
    elif norm == "bcrypt":
        # Extract cost factor if present
        cost = 10
        if sample_hash.startswith(("$2a$", "$2b$", "$2y$")):
            parts = sample_hash.split("$")
            if len(parts) >= 3 and parts[2].isdigit():
                cost = int(parts[2])

        if cost < 12:
            return (
                "acceptable",
                "MEDIUM",
                f"~120,000 H/s (Cost {cost})",
                "MODERATE (GPU-resistant, but cost factor should be increased)",
                f"Increase Bcrypt work factor from {cost} to minimum 12 (OWASP recommendation).",
            )
        else:
            return (
                "modern",
                "LOW",
                f"~35,000 H/s (Cost {cost})",
                "STRONG (Sufficient iteration resistance against classical hardware)",
                f"Maintain cost factor >= {cost}. Plan eventual transition to memory-hard Argon2id.",
            )
    elif norm == "pbkdf2_sha256":
        # Extract iterations if present
        iters = 100000
        if sample_hash.startswith(("$pbkdf2-sha256$", "pbkdf2_sha256$")):
            parts = sample_hash.split("$")
            if len(parts) >= 3 and parts[2].isdigit():
                iters = int(parts[2])

        if iters < 600000:
            return (
                "weak",
                "HIGH",
                f"~1.5 Million H/s (Iterations {iters:,})",
                "WEAK (Well below OWASP 2023+ recommendation of 600,000 iterations)",
                f"Increase PBKDF2 iterations to 600,000+ or replace with Argon2id.",
            )
        else:
            return (
                "acceptable",
                "MEDIUM",
                f"~150,000 H/s (Iterations {iters:,})",
                "MODERATE (Meets modern iteration standards, lacks memory hardness)",
                "Compliant with OWASP standards. Recommend evaluating Argon2id for new credentials.",
            )
    elif norm == "argon2":
        return (
            "modern",
            "LOW",
            "~1,200 H/s (64MB memory cost)",
            "EXCELLENT (Quantum & ASIC resistant via high memory hardness)",
            "Gold standard configuration. Fully compliant with NIST SP 800-63B and OWASP guidelines.",
        )
    else:
        return (
            "unknown",
            "MEDIUM",
            "Variable",
            "UNVERIFIED",
            "Identify origin algorithm and verify work factors against modern standards.",
        )


def analyze_crypto_hygiene(
    targets: Sequence[TargetCredential | str],
) -> CryptoHygieneReport:
    """Analyze the cryptographic posture of password hashes or parsed credential targets."""
    if not targets:
        return CryptoHygieneReport(
            total_hashes=0,
            overall_posture="NO_HASHES_PROVIDED",
            deprecated_count=0,
            findings=[],
            migration_roadmap=[],
        )

    # Normalize to (algorithm, sample_hash)
    algo_counts: Counter[str] = Counter()
    samples: dict[str, str] = {}

    for item in targets:
        if isinstance(item, TargetCredential):
            algo = item.hash_type
            raw_hash = item.hash_val
        else:
            raw_hash = str(item).strip()
            algo = detect_hash_type(raw_hash)

        algo_counts[algo] += 1
        if algo not in samples and raw_hash:
            samples[algo] = raw_hash

    findings: list[CryptoHygieneFinding] = []
    deprecated_count = 0
    has_critical = False
    has_high = False

    for algo, count in algo_counts.most_common():
        sample = samples.get(algo, "")
        status, risk, gpu_speed, pqc, rec = _evaluate_algorithm_hygiene(algo, sample)

        if risk == "CRITICAL":
            has_critical = True
            deprecated_count += count
        elif risk == "HIGH":
            has_high = True
            deprecated_count += count

        findings.append(
            CryptoHygieneFinding(
                algorithm=algo.upper(),
                status=status,
                count=count,
                risk_level=risk,
                gpu_cracking_speed=gpu_speed,
                pqc_readiness=pqc,
                recommendation=rec,
            )
        )

    # Determine overall fleet posture
    total = sum(algo_counts.values())
    if has_critical:
        posture = "CRITICAL RISK: DEPRECATED CRYPTOGRAPHIC ALGORITHMS DETECTED"
    elif has_high:
        posture = "ELEVATED RISK: WEAK / INSUFFICIENT KDF ITERATIONS"
    elif any(f.status == "acceptable" for f in findings):
        posture = "ACCEPTABLE POSTURE: LEGACY ALGORITHMS SHOULD BE HARDENED"
    else:
        posture = "MODERN POSTURE: FULLY HARDENED CREDENTIAL STORE"

    # Actionable migration roadmap
    roadmap = []
    if any(f.algorithm in ("NTLM", "LM") for f in findings):
        roadmap.append("1. Active Directory: Enforce NTLM blocking via Group Policy and mandate Kerberos with AES-256.")
    if any(f.algorithm in ("MD5", "MD5CRYPT", "SHA1") for f in findings):
        roadmap.append("2. Database Stores: Implement lazy re-hashing on user authentication to upgrade legacy MD5/SHA1 to Argon2id.")
    if any(f.algorithm == "BCRYPT" and f.status != "modern" for f in findings):
        roadmap.append("3. Bcrypt Work Factor: Update cost parameter in application code from <12 to cost factor 12+.")
    if any(f.algorithm == "PBKDF2_SHA256" and f.status != "modern" for f in findings):
        roadmap.append("4. PBKDF2 Iterations: Increase minimum iterations from current values to 600,000+ per OWASP recommendations.")
    roadmap.append("5. Target State: Standardize all future credential generation on Argon2id (m=65536, t=3, p=4).")

    return CryptoHygieneReport(
        total_hashes=total,
        overall_posture=posture,
        deprecated_count=deprecated_count,
        findings=findings,
        migration_roadmap=roadmap,
    )
