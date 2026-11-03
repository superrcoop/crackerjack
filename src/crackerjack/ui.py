"""Rich terminal interface and visualizations for Crackerjack."""

from __future__ import annotations

import os
from typing import Sequence

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from crackerjack import __version__
from crackerjack.models import (
    BenchmarkResult,
    CryptoHygieneReport,
    GeneratedPassphrase,
    HashAuditResult,
    HoneywordSet,
    PasswordHealthReport,
    ScanFinding,
)

console = Console()

BANNER_ART = r"""
   ______                __              _            __
  / ____/________ ______/ /_____  _____ (_)___ ______/ /__
 / /   / ___/ __ `/ ___/ //_/ _ \/ ___// / __ `/ ___/ //_/
/ /___/ /  / /_/ / /__/ ,< /  __/ /   / / /_/ / /__/ ,<
\____/_/   \__,_/\___/_/|_|\___/_/ __/ /\__,_/\___/_/|_|
                                  /___/      [v3.0.0]
"""


def show_banner() -> None:
    """Render the Crackerjack ASCII header banner."""
    banner_text = Text(BANNER_ART.strip(), style="bold cyan")
    subtitle = Text(
        f"Crackerjack {__version__} • Multi-Core NIST SP 800-63B Password Health & Breach Auditor\n"
        f"Detected {os.cpu_count() or 1} CPU cores • Defense-in-Depth Security Toolkit",
        style="dim white",
    )
    panel = Panel(
        Text.assemble(banner_text, "\n\n", subtitle),
        box=box.ROUNDED,
        border_style="cyan",
        expand=False,
    )
    console.print(panel)


def get_grade_style(grade: str) -> tuple[str, str]:
    """Return styling colors for a given NIST letter grade."""
    if grade in ("A+", "A"):
        return "bold white on green", "green"
    elif grade == "B":
        return "bold white on blue", "blue"
    elif grade == "C":
        return "bold black on yellow", "yellow"
    elif grade == "D":
        return "bold white on dark_orange", "dark_orange"
    else:
        return "bold white on red", "red"


def render_password_health(report: PasswordHealthReport) -> None:
    """Render comprehensive password health evaluation report."""
    nist = report.nist
    breach = report.breach
    badge_style, border_color = get_grade_style(nist.grade)

    table = Table(
        title=f"Health Audit: {report.password_masked}",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Security Metric", style="bold cyan", width=26)
    table.add_column("Evaluated Value", style="white", width=22)
    table.add_column("NIST SP 800-63B Standard", style="dim white")

    # Length
    len_status = "[green]Meets Recommended (>=15)" if nist.meets_recommended_length else (
        "[green]Passed Min (>=8)" if nist.passed_min_length else "[red]FAIL (<8 chars)"
    )
    table.add_row("Password Length", f"{nist.length} characters", len_status)

    # Entropy
    table.add_row(
        "Information Entropy",
        f"{nist.effective_entropy_bits:.1f} bits (eff) / {nist.raw_entropy_bits:.1f} (raw)",
        "NIST: >=70 bits recommended for high assurance",
    )

    # Character Diversity
    comp = nist.composition
    diversity_tags = []
    if comp.has_lower:
        diversity_tags.append("[green]a-z[/green]")
    if comp.has_upper:
        diversity_tags.append("[green]A-Z[/green]")
    if comp.has_digit:
        diversity_tags.append("[green]0-9[/green]")
    if comp.has_symbol:
        diversity_tags.append("[green]Symbols[/green]")
    table.add_row("Character Diversity", " ".join(diversity_tags) or "None", f"Pool Size: {comp.character_pool_size}")

    # Patterns
    pattern_status = []
    if nist.has_repetitive_pattern:
        pattern_status.append("[red]Repeated Chars[/red]")
    if nist.has_sequential_pattern:
        pattern_status.append("[red]Sequential Walk[/red]")
    if nist.is_dictionary_word:
        pattern_status.append("[red]Dictionary Root[/red]")
    table.add_row(
        "Pattern Flaws",
        ", ".join(pattern_status) if pattern_status else "[green]None detected[/green]",
        "NIST: Disallows known patterns and sequential walks",
    )

    # Breach Status
    if breach.offline:
        breach_text = f"[yellow]Offline ({breach.status_message})[/yellow]"
    elif breach.pwned:
        breach_text = f"[bold red]EXPOSED ({breach.breach_count:,} breaches)[/bold red]"
    else:
        breach_text = "[bold green]Clean (0 known breaches)[/bold green]"
    table.add_row("HaveIBeenPwned Breach", breach_text, "k-Anonymity SHA-1 lookup")

    # Context Terms Match (NIST SP 800-63B)
    if nist.has_context_words:
        terms_str = ", ".join(nist.matched_context_terms)
        table.add_row(
            "Context-Specific Match",
            f"[bold red]Matched: {terms_str}[/bold red]",
            "NIST: Disallows applicant/service names",
        )

    # Score & Grade
    table.add_row(
        "NIST Compliance Grade",
        f"[{badge_style}] {nist.grade} (Score: {nist.score}/100) [/{badge_style}]",
        f"Verdict: {report.verdict}",
    )

    console.print(table)

    # Recommendations
    rec_text = Text()
    for rec in nist.recommendations:
        rec_text.append(f" • {rec}\n", style="yellow" if "Avoid" in rec or "requires" in rec else "green")

    console.print(
        Panel(
            rec_text,
            title="[bold yellow]Remediation & NIST Recommendations[/bold yellow]",
            border_style=border_color,
            box=box.ROUNDED,
        )
    )


def create_audit_progress() -> Progress:
    """Create a Rich progress bar configured for high-speed hash auditing."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("•"),
        TextColumn("[yellow]{task.fields[rate]}"),
        TextColumn("•"),
        TimeElapsedColumn(),
        console=console,
    )


def render_audit_results(results: Sequence[HashAuditResult]) -> None:
    """Render a table summarizing the results of auditing target hashes."""
    table = Table(
        title="Multi-Core Hash Audit Results",
        box=box.ROUNDED,
        header_style="bold cyan",
    )
    table.add_column("Target Hash", style="dim", overflow="ellipsis", max_width=32)
    table.add_column("Algorithm", justify="center", style="cyan", width=10)
    table.add_column("Status", justify="center", width=12)
    table.add_column("Recovered Plaintext", style="bold yellow")
    table.add_column("Attempts", justify="right")
    table.add_column("Time (s)", justify="right")
    table.add_column("Hash Rate", justify="right", style="green")

    for res in results:
        status_text = "[bold red]CRACKED[/bold red]" if res.cracked else "[bold green]SECURE[/bold green]"
        pw_text = res.plaintext if res.cracked else "[dim]Not in wordlist[/dim]"
        table.add_row(
            res.target_hash,
            res.hash_type.upper(),
            status_text,
            pw_text,
            f"{res.attempts:,}",
            f"{res.elapsed_seconds:.2f}s",
            f"{res.hash_rate:.1f} H/s",
        )

    console.print(table)


def render_benchmark(res: BenchmarkResult) -> None:
    """Render the CPU core benchmark comparison."""
    table = Table(
        title=f"CPU Multiprocessing Benchmark ({res.algorithm.upper()} cost {res.cost_factor})",
        box=box.ROUNDED,
        header_style="bold magenta",
    )
    table.add_column("Configuration", style="bold cyan")
    table.add_column("Workers / Cores", justify="center")
    table.add_column("Throughput (H/s)", justify="right", style="green")
    table.add_column("Relative Speedup", justify="right", style="bold yellow")

    table.add_row("Single-Core Baseline", "1 worker", f"{res.single_core_rate:.2f} H/s", "1.00x")
    table.add_row(
        f"Multi-Core Engine ({res.workers} cores)",
        f"{res.workers} workers",
        f"{res.multi_core_rate:.2f} H/s",
        f"{res.speedup:.2f}x",
    )

    console.print(table)
    console.print(
        Panel(
            f"[bold green]Multi-core multiprocessing achieves a {res.speedup:.1f}x speedup[/bold green] "
            f"across {res.workers} CPU cores.\n"
            f"{res.algorithm.upper()} operations scale near-linearly with available hardware execution units.",
            border_style="green",
            box=box.ROUNDED,
        )
    )


def render_passphrase(res: GeneratedPassphrase) -> None:
    """Render the generated NIST-compliant passphrase with entropy metrics."""
    badge_style, border_style = get_grade_style(res.nist_grade)

    content = Text()
    content.append("Generated Passphrase:\n", style="dim")
    content.append(f"{res.passphrase}\n\n", style="bold green text_invert")
    content.append(f"• Word Count: ", style="dim")
    content.append(f"{res.word_count} words\n", style="bold white")
    content.append(f"• Theoretical Entropy: ", style="dim")
    content.append(f"{res.entropy_bits:.1f} bits\n", style="bold cyan")
    content.append(f"• Effective Shannon Entropy: ", style="dim")
    content.append(f"{res.effective_entropy_bits:.1f} bits\n", style="bold cyan")
    content.append(f"• NIST SP 800-63B Grade: ", style="dim")
    content.append(f" {res.nist_grade} ({res.nist_score}/100) \n", style=badge_style)

    if res.breached:
        content.append(f"• Breach Status: ", style="dim")
        content.append(f"CRITICAL: Found in {res.breach_count:,} public breaches!\n", style="bold red")
    else:
        content.append(f"• Breach Status: ", style="dim")
        content.append("Zero occurrences in known breach databases.\n", style="bold green")

    panel = Panel(
        content,
        title="[bold cyan]NIST SP 800-63B Certified Passphrase[/bold cyan]",
        box=box.ROUNDED,
        border_style="green" if res.nist_grade in ("A+", "A") else "yellow",
        expand=False,
    )
    console.print(panel)


def render_scan_results(findings: list[ScanFinding]) -> None:
    """Render repository secret scan findings."""
    if not findings:
        console.print(
            Panel(
                "[bold green]✓ Repository Clean:[/bold green] No hardcoded passwords or weak secrets detected.",
                border_style="green",
                box=box.ROUNDED,
            )
        )
        return

    table = Table(
        title=f"DevSecOps Repository Scan Findings ({len(findings)} exposed secrets detected)",
        box=box.ROUNDED,
        header_style="bold red",
    )
    table.add_column("Location", style="cyan")
    table.add_column("Variable", style="bold yellow")
    table.add_column("Masked Secret", style="dim")
    table.add_column("Score", justify="right")
    table.add_column("Grade", justify="center", width=8)
    table.add_column("Breach Status", justify="center")

    for f in findings:
        badge_style, _ = get_grade_style(f.nist_grade)
        breach_text = (
            f"[bold red]PWNED ({f.breach_count:,})[/bold red]"
            if f.breached
            else "[green]Clean[/green]"
        )
        table.add_row(
            f"{f.file_path}:{f.line_number}",
            f.variable_name,
            f.secret_masked,
            f"{f.nist_score}/100",
            Text(f" {f.nist_grade} ", style=badge_style),
            breach_text,
        )

    console.print(table)


def render_drift_history(drift: dict) -> None:
    """Render historical compliance drift and delta metrics."""
    history = drift.get("history", [])
    if not history:
        console.print(
            Panel(
                "[yellow]No historical audits found in ledger.[/yellow]\nRun `crackerjack audit <target> --track-history` to begin tracking.",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )
        return

    trend = drift.get("trend", "STABLE")
    trend_color = "green" if trend == "IMPROVING" else ("red" if trend == "DEGRADING" else "cyan")
    delta = drift.get("score_delta", 0)
    delta_str = f"+{delta}" if delta > 0 else str(delta)

    table = Table(
        title=f"Continuous Compliance Drift Ledger (Trend: [{trend_color}]{trend}[/{trend_color}] | Δ: {delta_str} pts)",
        box=box.ROUNDED,
        header_style="bold cyan",
    )
    table.add_column("Run ID", justify="right", style="dim")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Target Dump", style="bold")
    table.add_column("Evaluated", justify="right")
    table.add_column("Broken / Weak", justify="right", style="red")
    table.add_column("Score", justify="right")
    table.add_column("Grade", justify="center")
    table.add_column("PCI-DSS", justify="center")

    for entry in history:
        badge_style, _ = get_grade_style(entry.overall_grade)
        pci_badge = "[green]PASS[/green]" if entry.pci_dss_compliant else "[bold red]FAIL[/bold red]"
        table.add_row(
            str(entry.entry_id),
            entry.timestamp,
            entry.target_name,
            str(entry.total_evaluated),
            str(entry.total_broken),
            f"{entry.overall_score}/100",
            Text(f" {entry.overall_grade} ", style=badge_style),
            pci_badge,
        )

    console.print(table)


def render_crypto_hygiene(report: CryptoHygieneReport) -> None:
    """Render cryptographic posture and KDF hygiene report."""
    border_color = "red" if "CRITICAL" in report.overall_posture else ("yellow" if "ELEVATED" in report.overall_posture else "green")
    
    table = Table(
        title=f"Cryptographic Posture & KDF Hygiene Analysis ({report.total_hashes} hashes evaluated)",
        box=box.ROUNDED,
        header_style="bold magenta",
    )
    table.add_column("Algorithm", style="bold cyan")
    table.add_column("Count", justify="right")
    table.add_column("Status", justify="center")
    table.add_column("Risk Level", justify="center")
    table.add_column("Estimated GPU Cracking Speed", style="dim")
    table.add_column("NIST & OWASP Migration Guidance", style="yellow")

    for f in report.findings:
        status_color = "red" if f.status == "deprecated" else ("yellow" if f.status in ("weak", "acceptable") else "green")
        risk_color = "bold red" if f.risk_level == "CRITICAL" else ("red" if f.risk_level == "HIGH" else ("yellow" if f.risk_level == "MEDIUM" else "green"))
        table.add_row(
            f.algorithm,
            f"{f.count:,}",
            f"[{status_color}]{f.status.upper()}[/{status_color}]",
            f"[{risk_color}]{f.risk_level}[/{risk_color}]",
            f.gpu_cracking_speed,
            f.recommendation,
        )

    console.print(
        Panel(
            f"[bold {border_color}]{report.overall_posture}[/bold {border_color}]\nDeprecated Hashes Detected: {report.deprecated_count:,} of {report.total_hashes:,}",
            title="[bold]Fleet Security Posture[/bold]",
            border_style=border_color,
            box=box.ROUNDED,
        )
    )
    console.print(table)

    if report.migration_roadmap:
        roadmap_content = Text()
        for step in report.migration_roadmap:
            roadmap_content.append(f"  • {step}\n", style="cyan")
        console.print(
            Panel(
                roadmap_content,
                title="[bold green]Recommended KDF Modernization Roadmap[/bold green]",
                border_style="green",
                box=box.ROUNDED,
            )
        )


def render_honeyword_set(hset: HoneywordSet) -> None:
    """Render active deception honeyword set with canary tripwire information."""
    content = Text()
    content.append("Active Cyber Deception Canary Generated\n\n", style="bold cyan")
    content.append(f"Canary Identifier:  ", style="dim")
    content.append(f"{hset.canary_tag}\n", style="bold yellow")
    content.append(f"Total Decoys:       {hset.decoy_count}\n", style="dim")
    content.append(f"Entropy Parity:     {hset.avg_entropy_bits:.1f} bits\n\n", style="dim")
    content.append("Generated Honeyword Candidates (Decoys + Real Password mixed at random):\n", style="bold")

    for idx, hw in enumerate(hset.honeywords):
        content.append(f"  [{idx + 1}]  {hw}\n", style="green")

    content.append("\nTripwire Note: ", style="bold red")
    content.append("If any non-primary honeyword is submitted during authentication or cracked from a stolen dump, an instant SIEM incident alarm is tripped.\n", style="dim")

    console.print(
        Panel(
            content,
            title="[bold magenta]Honeyword Deception Generator[/bold magenta]",
            border_style="magenta",
            box=box.ROUNDED,
        )
    )

