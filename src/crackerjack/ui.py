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
    HashAuditResult,
    PasswordHealthReport,
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
