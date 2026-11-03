"""Unit tests for cryptographic hygiene, legacy KDF assessment, and migration analysis."""

from crackerjack.hygiene import analyze_crypto_hygiene
from crackerjack.models import TargetCredential


def test_analyze_crypto_hygiene_mixed_fleet():
    creds = [
        # Deprecated: NTLM & MD5
        TargetCredential(identity="user1", hash_val="31d6cfe0d16ae931b73c59d7e0c089c0", hash_type="ntlm"),
        TargetCredential(identity="user2", hash_val="$1$saltsalt$fakehashmd5", hash_type="md5"),
        # Modern: Bcrypt & Argon2id
        TargetCredential(identity="user3", hash_val="$2b$12$e8POdGlHFgqWq7GfQ1L46.kIeD5W3hF9qgJ4z7r0u6t5g8v9k3y5e", hash_type="bcrypt"),
        TargetCredential(identity="user4", hash_val="$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$fakeargon2hash", hash_type="argon2"),
    ]

    report = analyze_crypto_hygiene(creds)

    assert report.total_hashes == 4
    assert report.deprecated_count == 2
    assert "CRITICAL RISK" in report.overall_posture
    assert len(report.findings) == 4

    ntlm_finding = next(f for f in report.findings if f.algorithm == "NTLM")
    assert ntlm_finding.risk_level == "CRITICAL"
    assert ntlm_finding.status == "deprecated"
    assert "Billion" in ntlm_finding.gpu_cracking_speed

    argon_finding = next(f for f in report.findings if f.algorithm == "ARGON2")
    assert argon_finding.risk_level == "LOW"
    assert argon_finding.status == "modern"

    # Verify actionable roadmap
    assert len(report.migration_roadmap) >= 2
    assert any("Active Directory" in step for step in report.migration_roadmap)
    assert any("Argon2id" in step for step in report.migration_roadmap)


def test_analyze_crypto_hygiene_all_modern():
    creds = [
        TargetCredential(identity="u1", hash_val="$2b$12$e8POdGlHFgqWq7GfQ1L46.kIeD5W3hF9qgJ4z7r0u6t5g8v9k3y5e", hash_type="bcrypt"),
        TargetCredential(identity="u2", hash_val="$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$fakeargon2hash", hash_type="argon2"),
    ]

    report = analyze_crypto_hygiene(creds)
    assert report.total_hashes == 2
    assert report.deprecated_count == 0
    assert "MODERN POSTURE" in report.overall_posture
