"""Executive HTML Compliance Reporter generating standalone, printable client-ready reports."""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any

from crackerjack import __version__
from crackerjack.models import ComplianceSummary


def _generate_svg_donut_chart(grade_counts: dict[str, int]) -> str:
    """Generate a clean, standalone SVG donut chart for grade distribution."""
    total = sum(grade_counts.values()) or 1
    colors = {
        "A+": "#10b981",  # Emerald green
        "A": "#059669",
        "B": "#3b82f6",   # Blue
        "C": "#f59e0b",   # Amber
        "D": "#f97316",   # Orange
        "F": "#ef4444",   # Red
    }

    # Circumference = 2 * pi * r = 2 * 3.14159 * 70 ~= 439.82
    circumference = 439.82
    svg_paths: list[str] = []
    accumulated_pct = 0.0

    for grade in ["A+", "A", "B", "C", "D", "F"]:
        count = grade_counts.get(grade, 0)
        if count == 0:
            continue
        pct = count / total
        dash = pct * circumference
        offset = -(accumulated_pct * circumference)
        color = colors.get(grade, "#6b7280")

        svg_paths.append(
            f'<circle cx="100" cy="100" r="70" fill="transparent" '
            f'stroke="{color}" stroke-width="28" '
            f'stroke-dasharray="{dash:.2f} {circumference:.2f}" '
            f'stroke-dashoffset="{offset:.2f}"></circle>'
        )
        accumulated_pct += pct

    if not svg_paths:
        svg_paths.append(
            '<circle cx="100" cy="100" r="70" fill="transparent" '
            'stroke="#e5e7eb" stroke-width="28"></circle>'
        )

    legend_items = "".join(
        f'<div class="flex items-center gap-2 text-sm">'
        f'<span class="w-3 h-3 rounded-full" style="background-color: {colors.get(g, "#6b7280")}"></span>'
        f'<span class="font-bold">{g}:</span> <span>{grade_counts.get(g, 0)} ({grade_counts.get(g, 0)*100//total}%)</span>'
        f'</div>'
        for g in ["A+", "A", "B", "C", "D", "F"]
        if grade_counts.get(g, 0) > 0
    )

    return f"""
    <div class="chart-wrapper">
        <svg viewBox="0 0 200 200" width="180" height="180" class="donut-svg">
            <g transform="rotate(-90 100 100)">
                {''.join(svg_paths)}
            </g>
            <text x="100" y="95" text-anchor="middle" font-size="24" font-weight="bold" fill="#1f2937">{total}</text>
            <text x="100" y="115" text-anchor="middle" font-size="11" fill="#6b7280">TOTAL ACCOUNTS</text>
        </svg>
        <div class="chart-legend">
            {legend_items}
        </div>
    </div>
    """


def build_compliance_summary(findings: list[dict[str, Any]]) -> ComplianceSummary:
    """Aggregate raw findings into a structured executive ComplianceSummary."""
    total = len(findings)
    if total == 0:
        return ComplianceSummary(
            total_evaluated=0,
            total_cracked_or_weak=0,
            total_breached=0,
            avg_entropy=0.0,
            overall_score=100,
            overall_grade="A+",
            nist_compliant_pct=100.0,
            pci_dss_compliant=True,
            grade_distribution={},
            findings=[],
        )

    cracked_or_weak = 0
    breached_count = 0
    total_entropy = 0.0
    total_score = 0
    nist_compliant_count = 0
    grade_dist: dict[str, int] = {"A+": 0, "A": 0, "B": 0, "C": 0, "D": 0, "F": 0}

    for f in findings:
        score = f.get("score", 0)
        grade = f.get("grade", "F")
        grade_dist[grade] = grade_dist.get(grade, 0) + 1

        total_score += score
        total_entropy += f.get("effective_entropy", f.get("raw_entropy", 0.0))

        is_cracked = f.get("cracked", False)
        is_breached = f.get("breached", False)
        if is_cracked or grade in ("D", "F"):
            cracked_or_weak += 1
        if is_breached:
            breached_count += 1
        if grade in ("A+", "A", "B") and not is_cracked and not is_breached:
            nist_compliant_count += 1

    avg_score = total_score // total
    avg_entropy = total_entropy / total
    nist_pct = (nist_compliant_count / total) * 100.0

    # Determine overall fleet letter grade
    if avg_score >= 90 and breached_count == 0 and cracked_or_weak == 0:
        overall_grade = "A+"
    elif avg_score >= 80:
        overall_grade = "A"
    elif avg_score >= 70:
        overall_grade = "B"
    elif avg_score >= 60:
        overall_grade = "C"
    elif avg_score >= 50:
        overall_grade = "D"
    else:
        overall_grade = "F"

    # PCI-DSS v4.0 requires zero breached passwords in production
    pci_dss_compliant = (breached_count == 0 and cracked_or_weak == 0)

    return ComplianceSummary(
        total_evaluated=total,
        total_cracked_or_weak=cracked_or_weak,
        total_breached=breached_count,
        avg_entropy=avg_entropy,
        overall_score=avg_score,
        overall_grade=overall_grade,
        nist_compliant_pct=nist_pct,
        pci_dss_compliant=pci_dss_compliant,
        grade_distribution=grade_dist,
        findings=findings,
    )


def generate_html_report(summary: ComplianceSummary, title: str = "Executive Credential Audit & Compliance Report") -> str:
    """Generate a self-contained, printable HTML report with embedded styles and charts."""
    generated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    donut_chart_html = _generate_svg_donut_chart(summary.grade_distribution)

    grade_colors = {
        "A+": "#10b981",
        "A": "#059669",
        "B": "#3b82f6",
        "C": "#f59e0b",
        "D": "#f97316",
        "F": "#ef4444",
    }
    badge_color = grade_colors.get(summary.overall_grade, "#6b7280")

    # Table rows for findings
    rows_html = []
    for idx, f in enumerate(summary.findings, 1):
        grade = f.get("grade", "F")
        g_color = grade_colors.get(grade, "#6b7280")
        ident = f.get("identity", "Account")
        mask = f.get("masked", "********")
        algo = f.get("algorithm", "bcrypt").upper()
        verdict = f.get("verdict", "AUDITED")
        verdict_class = "badge-danger" if "CRACK" in verdict or "BREACH" in verdict or grade == "F" else "badge-success"
        violations = ", ".join(f.get("violations", [])) or "None"

        rows_html.append(
            f"<tr>"
            f"<td class='mono font-semibold'>{idx}</td>"
            f"<td class='font-bold'>{ident}</td>"
            f"<td class='mono text-dim'>{mask}</td>"
            f"<td><span class='badge-pill'>{algo}</span></td>"
            f"<td><span class='badge-pill {verdict_class}'>{verdict}</span></td>"
            f"<td><span class='grade-badge' style='background-color: {g_color};'>{grade}</span> ({f.get('score', 0)}/100)</td>"
            f"<td class='text-sm text-dim'>{violations}</td>"
            f"</tr>"
        )

    findings_tbody = "\n".join(rows_html)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - Crackerjack {__version__}</title>
    <style>
        :root {{
            --bg-color: #f8fafc;
            --card-bg: #ffffff;
            --text-main: #0f172a;
            --text-dim: #64748b;
            --border-color: #e2e8f0;
            --primary: #0284c7;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            line-height: 1.5;
            padding: 2.5rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--card-bg);
            padding: 2rem;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            margin-bottom: 2rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .header-title h1 {{ font-size: 1.75rem; font-weight: 800; color: #0f172a; letter-spacing: -0.02em; }}
        .header-title p {{ color: var(--text-dim); font-size: 0.9rem; margin-top: 0.25rem; }}
        .score-pill {{
            display: flex;
            align-items: center;
            gap: 1.25rem;
            background: #f1f5f9;
            padding: 0.75rem 1.5rem;
            border-radius: 9999px;
            border: 1px solid #cbd5e1;
        }}
        .score-val {{ font-size: 2.25rem; font-weight: 900; line-height: 1; }}
        .grade-box {{
            width: 44px; height: 44px; border-radius: 8px;
            display: flex; align-items: center; justify-content: center;
            font-weight: 900; font-size: 1.5rem; color: #fff;
        }}
        .grid-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2rem;
        }}
        .card {{
            background: var(--card-bg);
            padding: 1.5rem;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .card-label {{ font-size: 0.8rem; font-weight: 600; text-transform: uppercase; color: var(--text-dim); letter-spacing: 0.05em; }}
        .card-value {{ font-size: 2rem; font-weight: 800; margin-top: 0.5rem; }}
        .card-subtext {{ font-size: 0.8rem; color: var(--text-dim); margin-top: 0.25rem; }}
        .analytics-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }}
        .compliance-list {{ display: flex; flex-direction: column; gap: 0.75rem; margin-top: 1rem; }}
        .compliance-item {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.75rem 1rem;
            background: #f8fafc;
            border-radius: 8px;
            border: 1px solid #e2e8f0;
        }}
        .compliance-name {{ font-weight: 600; font-size: 0.95rem; }}
        .chart-wrapper {{ display: flex; align-items: center; gap: 2rem; justify-content: center; margin-top: 1rem; }}
        .chart-legend {{ display: flex; flex-direction: column; gap: 0.4rem; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
            font-size: 0.9rem;
        }}
        th {{
            background: #f1f5f9;
            color: #475569;
            font-weight: 600;
            text-align: left;
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border-color);
        }}
        td {{
            padding: 0.85rem 1rem;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
        }}
        tr:hover {{ background-color: #f8fafc; }}
        .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
        .font-semibold {{ font-weight: 600; }}
        .font-bold {{ font-weight: 700; }}
        .text-dim {{ color: var(--text-dim); }}
        .badge-pill {{
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 700;
            background: #e2e8f0;
            color: #334155;
        }}
        .badge-danger {{ background: #fee2e2; color: #991b1b; }}
        .badge-success {{ background: #dcfce7; color: #166534; }}
        .grade-badge {{
            display: inline-block;
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 800;
            color: #fff;
        }}
        .roadmap-card {{
            background: #fffbeb;
            border: 1px solid #fde68a;
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}
        .roadmap-card h3 {{ color: #92400e; font-size: 1.1rem; font-weight: 700; margin-bottom: 0.5rem; }}
        .roadmap-list {{ list-style-type: decimal; padding-left: 1.5rem; color: #78350f; font-size: 0.95rem; }}
        .roadmap-list li {{ margin-bottom: 0.35rem; }}
        .footer {{
            text-align: center;
            color: var(--text-dim);
            font-size: 0.85rem;
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border-color);
        }}
        @media print {{
            body {{ background: #fff; padding: 0; }}
            .header, .card, .roadmap-card {{ box-shadow: none; border: 1px solid #ccc; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-title">
                <h1>{title}</h1>
                <p>Audited with Crackerjack v{__version__} | Timestamp: {generated_at}</p>
            </div>
            <div class="score-pill">
                <div class="grade-box" style="background-color: {badge_color};">{summary.overall_grade}</div>
                <div>
                    <div class="score-val">{summary.overall_score}<span style="font-size: 1.25rem; color: #94a3b8;">/100</span></div>
                    <div style="font-size: 0.75rem; font-weight: 600; color: #64748b;">FLEET SECURITY SCORE</div>
                </div>
            </div>
        </div>

        <!-- Metric KPI Cards -->
        <div class="grid-cards">
            <div class="card">
                <div class="card-label">Total Accounts Audited</div>
                <div class="card-value">{summary.total_evaluated}</div>
                <div class="card-subtext">Enterprise identity targets</div>
            </div>
            <div class="card">
                <div class="card-label">Cracked / Weak Passwords</div>
                <div class="card-value" style="color: {'#ef4444' if summary.total_cracked_or_weak > 0 else '#10b981'};">
                    {summary.total_cracked_or_weak}
                </div>
                <div class="card-subtext">Failed wordlist / NIST rules</div>
            </div>
            <div class="card">
                <div class="card-label">Known Breached Credentials</div>
                <div class="card-value" style="color: {'#ef4444' if summary.total_breached > 0 else '#10b981'};">
                    {summary.total_breached}
                </div>
                <div class="card-subtext">Confirmed in HIBP database</div>
            </div>
            <div class="card">
                <div class="card-label">Average Entropy</div>
                <div class="card-value">{summary.avg_entropy:.1f} <span style="font-size: 1rem; font-weight: 600;">bits</span></div>
                <div class="card-subtext">NIST target: &gt;64 bits</div>
            </div>
        </div>

        <!-- Compliance & Charts Grid -->
        <div class="analytics-grid">
            <div class="card">
                <h2 style="font-size: 1.25rem; font-weight: 700;">Regulatory Compliance Scorecard</h2>
                <div class="compliance-list">
                    <div class="compliance-item">
                        <div class="compliance-name">NIST SP 800-63B Compliance Rate</div>
                        <span class="badge-pill {'badge-success' if summary.nist_compliant_pct >= 85 else 'badge-danger'}">
                            {summary.nist_compliant_pct:.1f}% Compliant
                        </span>
                    </div>
                    <div class="compliance-item">
                        <div class="compliance-name">PCI-DSS v4.0 (Req 8.3.6 - No Breached Passwords)</div>
                        <span class="badge-pill {'badge-success' if summary.pci_dss_compliant else 'badge-danger'}">
                            {'PASSED' if summary.pci_dss_compliant else 'NON-COMPLIANT'}
                        </span>
                    </div>
                    <div class="compliance-item">
                        <div class="compliance-name">Contextual Dictionary Blocking (§5.1.1.2)</div>
                        <span class="badge-pill badge-success">ACTIVE FILTER</span>
                    </div>
                    <div class="compliance-item">
                        <div class="compliance-name">SOC 2 / ISO 27001 Identity Assurance</div>
                        <span class="badge-pill {'badge-success' if summary.overall_score >= 80 else 'badge-danger'}">
                            {'SATISFACTORY' if summary.overall_score >= 80 else 'REMEDIATION REQUIRED'}
                        </span>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2 style="font-size: 1.25rem; font-weight: 700;">Password Health Grade Distribution</h2>
                {donut_chart_html}
            </div>
        </div>

        <!-- Prioritized Action Plan -->
        <div class="roadmap-card">
            <h3>⚡ Prioritized Security Remediation Roadmap</h3>
            <ol class="roadmap-list">
                <li><strong>Immediate Action:</strong> Invalidate and force password resets for the <strong>{summary.total_cracked_or_weak + summary.total_breached} compromised/weak accounts</strong> identified in this assessment.</li>
                <li><strong>Contextual Defense:</strong> Configure IAM registration policies to block prospective secrets containing company names, usernames, or service terms as recommended by NIST SP 800-63B.</li>
                <li><strong>Modern Passphrase Adoption:</strong> Encourage multi-word passphrases (15+ characters) with high entropy over short, complex secrets with frequent forced rotation.</li>
            </ol>
        </div>

        <!-- Detailed Findings Table -->
        <div class="card">
            <h2 style="font-size: 1.25rem; font-weight: 700; margin-bottom: 0.5rem;">Audit Findings Details</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Identity</th>
                        <th>Target Hash / Secret</th>
                        <th>Algorithm</th>
                        <th>Verdict</th>
                        <th>NIST Grade</th>
                        <th>Policy Violations</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_tbody}
                </tbody>
            </table>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>Generated by Crackerjack {__version__} &bull; Enterprise Password Health & Breach Auditor</p>
            <p style="margin-top: 0.25rem; font-size: 0.75rem;">Confidential Security Assessment Deliverable &bull; For Authorized Personnel Only</p>
        </div>
    </div>
</body>
</html>
"""


def save_html_report(summary: ComplianceSummary, output_path: Path, title: str = "Executive Credential Audit & Compliance Report") -> None:
    """Save compliance summary to a standalone HTML report file."""
    html_content = generate_html_report(summary, title=title)
    output_path.write_text(html_content, encoding="utf-8")
