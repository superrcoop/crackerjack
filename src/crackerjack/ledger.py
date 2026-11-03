"""Historical Compliance Drift & Audit Ledger backed by SQLite."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
import sqlite3
from typing import Any

from crackerjack.models import AuditLedgerEntry, ComplianceSummary


def get_default_db_path() -> Path:
    """Return default path to user-level ledger database with fallback for sandboxes."""
    try:
        db_dir = Path.home() / ".crackerjack"
        db_dir.mkdir(parents=True, exist_ok=True)
        return db_dir / "ledger.db"
    except Exception:
        fallback = Path("/tmp") / ".crackerjack"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback / "ledger.db"


def init_db(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Initialize the SQLite ledger database and create tables if missing."""
    target = Path(db_path) if db_path else get_default_db_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(target))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            target_name TEXT NOT NULL,
            total_evaluated INTEGER NOT NULL,
            total_broken INTEGER NOT NULL,
            avg_entropy REAL NOT NULL,
            overall_score INTEGER NOT NULL,
            overall_grade TEXT NOT NULL,
            nist_compliant_pct REAL NOT NULL,
            pci_dss_compliant INTEGER NOT NULL,
            metadata_json TEXT
        );
        """
    )
    conn.commit()
    return conn


def record_audit(
    summary: ComplianceSummary,
    target_name: str,
    db_path: Path | str | None = None,
) -> AuditLedgerEntry:
    """Record an audit run into the persistent SQLite ledger."""
    conn = init_db(db_path)
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO audit_runs (
            timestamp, target_name, total_evaluated, total_broken,
            avg_entropy, overall_score, overall_grade, nist_compliant_pct,
            pci_dss_compliant, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            now_iso,
            target_name,
            summary.total_evaluated,
            summary.total_cracked_or_weak,
            summary.avg_entropy,
            summary.overall_score,
            summary.overall_grade,
            summary.nist_compliant_pct,
            1 if summary.pci_dss_compliant else 0,
            json.dumps({"grade_distribution": summary.grade_distribution}),
        ),
    )
    conn.commit()
    entry_id = cursor.lastrowid
    conn.close()

    return AuditLedgerEntry(
        entry_id=entry_id,
        timestamp=now_iso,
        target_name=target_name,
        total_evaluated=summary.total_evaluated,
        total_broken=summary.total_cracked_or_weak,
        avg_entropy=summary.avg_entropy,
        overall_score=summary.overall_score,
        overall_grade=summary.overall_grade,
        nist_compliant_pct=summary.nist_compliant_pct,
        pci_dss_compliant=summary.pci_dss_compliant,
    )


def get_audit_history(
    limit: int = 50,
    db_path: Path | str | None = None,
) -> list[AuditLedgerEntry]:
    """Retrieve historical audit entries ordered from earliest to latest."""
    conn = init_db(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, timestamp, target_name, total_evaluated, total_broken,
               avg_entropy, overall_score, overall_grade, nist_compliant_pct,
               pci_dss_compliant
        FROM audit_runs
        ORDER BY id DESC
        LIMIT ?;
        """,
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()

    entries = [
        AuditLedgerEntry(
            entry_id=r[0],
            timestamp=r[1],
            target_name=r[2],
            total_evaluated=r[3],
            total_broken=r[4],
            avg_entropy=r[5],
            overall_score=r[6],
            overall_grade=r[7],
            nist_compliant_pct=r[8],
            pci_dss_compliant=bool(r[9]),
        )
        for r in rows
    ]
    # Return in chronological order
    entries.reverse()
    return entries


def calculate_drift(db_path: Path | str | None = None) -> dict[str, Any]:
    """Calculate compliance drift between recent audit runs."""
    history = get_audit_history(limit=10, db_path=db_path)
    if not history:
        return {
            "runs_count": 0,
            "latest_score": 0,
            "previous_score": None,
            "score_delta": 0,
            "broken_delta": 0,
            "trend": "INSUFFICIENT_DATA",
            "history": [],
        }

    latest = history[-1]
    prev = history[-2] if len(history) >= 2 else None

    score_delta = (latest.overall_score - prev.overall_score) if prev else 0
    broken_delta = (latest.total_broken - prev.total_broken) if prev else 0

    if score_delta > 0:
        trend = "IMPROVING"
    elif score_delta < 0:
        trend = "DEGRADING"
    else:
        trend = "STABLE"

    return {
        "runs_count": len(history),
        "latest_score": latest.overall_score,
        "previous_score": prev.overall_score if prev else None,
        "score_delta": score_delta,
        "broken_delta": broken_delta,
        "trend": trend,
        "history": history,
    }


def generate_drift_svg_chart(history: list[AuditLedgerEntry], width: int = 600, height: int = 180) -> str:
    """Generate an inline SVG trendline graph visualizing health score drift over time."""
    if not history or len(history) < 2:
        return (
            '<div style="text-align:center; padding:20px; color:#8b949e; font-size:12px;">'
            'Historical trend graph requires at least 2 audit runs in the ledger.</div>'
        )

    padding = 40
    plot_w = width - (padding * 2)
    plot_h = height - (padding * 2)

    scores = [h.overall_score for h in history]
    min_score = max(0, min(scores) - 10)
    max_score = min(100, max(scores) + 10)
    y_range = max(1, max_score - min_score)

    step_x = plot_w / (len(history) - 1)

    points = []
    svg_circles = []
    for idx, h in enumerate(history):
        cx = padding + (idx * step_x)
        # Invert y: high score is top
        cy = padding + plot_h - (((h.overall_score - min_score) / y_range) * plot_h)
        points.append(f"{cx:.1f},{cy:.1f}")

        color = "#2ea043" if h.overall_score >= 80 else ("#d29922" if h.overall_score >= 60 else "#f85149")
        svg_circles.append(
            f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="4" fill="{color}" stroke="#0d1117" stroke-width="2">'
            f'<title>Run #{h.entry_id} ({h.timestamp}): Score {h.overall_score}/100</title></circle>'
        )

    polyline = " ".join(points)

    svg = f"""<svg width="100%" height="{height}" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="driftGradient" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#58a6ff" stop-opacity="0.3"/>
      <stop offset="100%" stop-color="#58a6ff" stop-opacity="0.0"/>
    </linearGradient>
  </defs>
  <!-- Grid Lines -->
  <line x1="{padding}" y1="{padding}" x2="{width - padding}" y2="{padding}" stroke="#30363d" stroke-dasharray="3,3" />
  <line x1="{padding}" y1="{padding + plot_h/2}" x2="{width - padding}" y2="{padding + plot_h/2}" stroke="#30363d" stroke-dasharray="3,3" />
  <line x1="{padding}" y1="{padding + plot_h}" x2="{width - padding}" y2="{padding + plot_h}" stroke="#30363d" stroke-dasharray="3,3" />
  
  <!-- Y-Axis Labels -->
  <text x="{padding - 8}" y="{padding + 4}" fill="#8b949e" font-size="10" text-anchor="end">{max_score}</text>
  <text x="{padding - 8}" y="{padding + plot_h/2 + 4}" fill="#8b949e" font-size="10" text-anchor="end">{int((max_score + min_score)/2)}</text>
  <text x="{padding - 8}" y="{padding + plot_h + 4}" fill="#8b949e" font-size="10" text-anchor="end">{min_score}</text>

  <!-- Trend Line -->
  <polyline fill="none" stroke="#58a6ff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" points="{polyline}" />
  {' '.join(svg_circles)}
</svg>"""
    return svg
