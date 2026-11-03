"""Unit tests for SQLite audit ledger and compliance drift tracking."""

from pathlib import Path

from crackerjack.ledger import (
    calculate_drift,
    generate_drift_svg_chart,
    get_audit_history,
    init_db,
    record_audit,
)
from crackerjack.models import ComplianceSummary


def _create_sample_summary(score: int, broken: int, grade: str) -> ComplianceSummary:
    return ComplianceSummary(
        total_evaluated=20,
        total_cracked_or_weak=broken,
        total_breached=0,
        avg_entropy=65.0,
        overall_score=score,
        overall_grade=grade,
        nist_compliant_pct=float(score),
        pci_dss_compliant=(broken == 0),
        grade_distribution={grade: 20},
        findings=[],
    )


def test_record_and_get_audit_history(tmp_path: Path):
    db_file = tmp_path / "test_ledger.db"
    conn = init_db(db_file)
    conn.close()

    s1 = _create_sample_summary(score=70, broken=5, grade="B")
    s2 = _create_sample_summary(score=85, broken=2, grade="A")

    e1 = record_audit(s1, target_name="dump_q1.txt", db_path=db_file)
    e2 = record_audit(s2, target_name="dump_q2.txt", db_path=db_file)

    assert e1.entry_id == 1
    assert e2.entry_id == 2
    assert e1.overall_score == 70
    assert e2.overall_score == 85

    history = get_audit_history(limit=10, db_path=db_file)
    assert len(history) == 2
    # Chronological ordering
    assert history[0].entry_id == 1
    assert history[1].entry_id == 2


def test_calculate_drift(tmp_path: Path):
    db_file = tmp_path / "drift_test.db"

    # 1. Empty ledger
    empty_drift = calculate_drift(db_path=db_file)
    assert empty_drift["runs_count"] == 0
    assert empty_drift["trend"] == "INSUFFICIENT_DATA"

    # 2. First run
    s1 = _create_sample_summary(score=60, broken=8, grade="C")
    record_audit(s1, "initial_audit", db_path=db_file)
    d1 = calculate_drift(db_path=db_file)
    assert d1["runs_count"] == 1
    assert d1["score_delta"] == 0
    assert d1["trend"] == "STABLE"

    # 3. Second run (Improving)
    s2 = _create_sample_summary(score=85, broken=2, grade="A")
    record_audit(s2, "hardened_audit", db_path=db_file)
    d2 = calculate_drift(db_path=db_file)
    assert d2["runs_count"] == 2
    assert d2["score_delta"] == 25  # +25 points
    assert d2["broken_delta"] == -6  # 6 fewer broken passwords
    assert d2["trend"] == "IMPROVING"


def test_generate_drift_svg_chart(tmp_path: Path):
    db_file = tmp_path / "chart_test.db"
    record_audit(_create_sample_summary(65, 6, "B"), "run1", db_path=db_file)
    record_audit(_create_sample_summary(80, 2, "A"), "run2", db_path=db_file)
    record_audit(_create_sample_summary(92, 0, "A+"), "run3", db_path=db_file)

    history = get_audit_history(db_path=db_file)
    svg = generate_drift_svg_chart(history)

    assert "<svg" in svg
    assert "</svg>" in svg
    assert "<polyline" in svg
    assert "<circle" in svg
    assert "Score 92/100" in svg
