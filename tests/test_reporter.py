"""Tests for executive HTML compliance report generator."""

from pathlib import Path

from crackerjack.reporter import (
    build_compliance_summary,
    generate_html_report,
    save_html_report,
)


def test_build_compliance_summary_clean():
    findings = [
        {
            "identity": "alice",
            "masked": "Correct-Horse-Bat-2026!",
            "algorithm": "bcrypt",
            "verdict": "SECURE",
            "score": 90,
            "grade": "A+",
            "violations": [],
            "cracked": False,
            "breached": False,
        },
        {
            "identity": "bob",
            "masked": "Battery-Staple-Safe!",
            "algorithm": "argon2",
            "verdict": "SECURE",
            "score": 85,
            "grade": "A",
            "violations": [],
            "cracked": False,
            "breached": False,
        },
    ]

    summary = build_compliance_summary(findings)
    assert summary.total_evaluated == 2
    assert summary.total_cracked_or_weak == 0
    assert summary.total_breached == 0
    assert summary.pci_dss_compliant is True
    assert summary.overall_score >= 85
    assert summary.overall_grade in ("A+", "A")
    assert summary.nist_compliant_pct == 100.0


def test_build_compliance_summary_with_cracked():
    findings = [
        {
            "identity": "admin",
            "masked": "p***1",
            "algorithm": "bcrypt",
            "verdict": "CRACKED",
            "score": 25,
            "grade": "F",
            "violations": ["Dictionary word root", "Short (<8 chars)"],
            "cracked": True,
            "breached": False,
        },
    ]

    summary = build_compliance_summary(findings)
    assert summary.total_evaluated == 1
    assert summary.total_cracked_or_weak == 1
    assert summary.pci_dss_compliant is False
    assert summary.overall_grade == "F"


def test_generate_and_save_html_report(tmp_path: Path):
    findings = [
        {
            "identity": "user1",
            "masked": "pass***1",
            "algorithm": "bcrypt",
            "verdict": "CRACKED",
            "score": 30,
            "grade": "F",
            "violations": ["Context match: acme"],
            "cracked": True,
            "breached": False,
        }
    ]

    summary = build_compliance_summary(findings)
    report_file = tmp_path / "audit_report.html"

    save_html_report(summary, report_file, title="Test Audit Report")
    assert report_file.exists()

    content = report_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "Test Audit Report" in content
    assert "NIST SP 800-63B" in content
    assert "PCI-DSS v4.0" in content
    assert "donut-svg" in content
    assert "user1" in content
