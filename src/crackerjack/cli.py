"""Typer CLI interface for Crackerjack 3.0."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Annotated, Optional

import bcrypt
import typer

from crackerjack import __version__
from crackerjack.auditor import evaluate_password
from crackerjack.breach import check_password_breached
from crackerjack.engine import (
    MultiCoreAuditEngine,
    is_bcrypt_hash,
    run_benchmark,
)
from crackerjack.models import (
    BreachInfo,
    PasswordHealthReport,
)
from crackerjack.rules import mutate_word
from crackerjack.ui import (
    console,
    create_audit_progress,
    render_audit_results,
    render_benchmark,
    render_password_health,
    show_banner,
)

app = typer.Typer(
    name="crackerjack",
    help="Crackerjack 3.0: Modern Multi-Core Password Health Auditor & NIST SP 800-63B Compliance Checker",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def main_callback() -> None:
    """Crackerjack 3.0 Security & Audit Suite."""


@app.command(name="check")
def check_command(
    password: Annotated[
        Optional[str],
        typer.Argument(help="Plaintext password to evaluate (prompted securely if omitted)"),
    ] = None,
    no_hibp: Annotated[
        bool,
        typer.Option("--no-hibp", help="Skip HaveIBeenPwned network check (offline mode)"),
    ] = False,
    show_plaintext: Annotated[
        bool,
        typer.Option("--show-plaintext", "-s", help="Do not mask the password in output"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output report in JSON format"),
    ] = False,
) -> None:
    """Audit the health, entropy, and breach status of a plaintext password according to NIST SP 800-63B."""
    if not password:
        password = typer.prompt("Enter password to evaluate", hide_input=True)

    if not password:
        console.print("[red]Error: Empty password provided.[/red]")
        raise typer.Exit(code=1)

    nist_eval = evaluate_password(password)

    if no_hibp:
        breach_info = BreachInfo(
            pwned=False,
            breach_count=0,
            offline=True,
            status_message="HaveIBeenPwned check disabled by --no-hibp flag.",
        )
    else:
        breach_info = check_password_breached(password)

    # Determine verdict
    if breach_info.pwned:
        verdict = "[bold red]COMPROMISED (Found in data breaches)[/bold red]"
    elif nist_eval.grade in ("A+", "A"):
        verdict = "[bold green]EXCELLENT (Exceeds NIST recommendations)[/bold green]"
    elif nist_eval.grade == "B":
        verdict = "[bold blue]STRONG (Compliant with NIST recommendations)[/bold blue]"
    elif nist_eval.grade == "C":
        verdict = "[bold yellow]FAIR (Meets baseline length, low complexity)[/bold yellow]"
    elif nist_eval.grade == "D":
        verdict = "[bold dark_orange]POOR (Susceptible to attacks)[/bold dark_orange]"
    else:
        verdict = "[bold red]CRITICAL (Violates NIST SP 800-63B baseline)[/bold red]"

    masked = password if show_plaintext else (password[0] + "*" * (len(password) - 2) + password[-1] if len(password) > 2 else "***")

    report = PasswordHealthReport(
        password_masked=masked,
        nist=nist_eval,
        breach=breach_info,
        verdict=verdict,
        summary=f"Score {nist_eval.score}/100, Grade {nist_eval.grade}",
    )

    if json_output:
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        show_banner()
        render_password_health(report)

    if breach_info.pwned or nist_eval.grade in ("D", "F"):
        raise typer.Exit(code=1)


@app.command(name="hash")
def hash_command(
    password: Annotated[
        Optional[str],
        typer.Argument(help="Plaintext password to hash with bcrypt (prompted securely if omitted)"),
    ] = None,
    cost: Annotated[
        int,
        typer.Option("--cost", "-c", min=4, max=31, help="Bcrypt cost factor (work factor)"),
    ] = 12,
) -> None:
    """Generate a cryptographically secure bcrypt hash for a plaintext password."""
    if not password:
        password = typer.prompt("Enter password to hash", hide_input=True)

    pw_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=cost)
    hashed = bcrypt.hashpw(pw_bytes, salt)
    hash_str = hashed.decode("ascii")

    console.print(f"[bold green]Bcrypt Hash (cost {cost}):[/bold green] [bold white]{hash_str}[/bold white]")


def _load_lines_from_path(file_path: Path) -> list[str]:
    """Read non-empty lines from a file."""
    if not file_path.exists():
        console.print(f"[red]Error: File not found: {file_path}[/red]")
        raise typer.Exit(code=1)

    lines: list[str] = []
    with file_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                lines.append(stripped)
    return lines


def _stream_wordlist_candidates(
    wordlist_path: Path,
    use_rules: bool = True,
) -> list[str]:
    """Stream candidate words from a wordlist, optionally applying mutation rules."""
    words = _load_lines_from_path(wordlist_path)
    if not use_rules:
        return words

    seen: set[str] = set()
    candidates: list[str] = []
    for w in words:
        for variant in mutate_word(w):
            if variant not in seen:
                seen.add(variant)
                candidates.append(variant)
    return candidates


@app.command(name="audit")
def audit_command(
    target: Annotated[
        Path,
        typer.Argument(
            help="Path to file containing hashes (or plaintexts) or single hash string",
            metavar="TARGET",
        ),
    ],
    wordlist: Annotated[
        Optional[Path],
        typer.Option(
            "--wordlist",
            "-w",
            help="Path to dictionary wordlist (e.g. rockyou.txt or samplewords.txt)",
        ),
    ] = None,
    workers: Annotated[
        int,
        typer.Option(
            "--workers",
            help="Number of parallel CPU worker processes (defaults to all CPU cores)",
        ),
    ] = os.cpu_count() or 1,
    rules: Annotated[
        bool,
        typer.Option(
            "--rules/--no-rules",
            help="Apply hybrid rule mutations (leetspeak, numbers, case) to wordlist",
        ),
    ] = True,
    chunk_size: Annotated[
        int,
        typer.Option("--chunk-size", help="Batch size per worker process"),
    ] = 100,
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Write audit results to JSON file"),
    ] = None,
) -> None:
    """Audit hashes or passwords using multi-core multiprocessing and wordlists."""
    show_banner()

    target_str = str(target)
    target_hashes: list[str] = []

    if Path(target).is_file():
        raw_lines = _load_lines_from_path(Path(target))
        # Determine if lines are hashes or plaintexts
        for line in raw_lines:
            if is_bcrypt_hash(line):
                target_hashes.append(line)
            else:
                # Could be a hash on a line with username:hash
                parts = line.split(":")
                for p in parts:
                    if is_bcrypt_hash(p.strip()):
                        target_hashes.append(p.strip())
                        break
        if not target_hashes:
            # Check if this is a plaintext list to audit
            console.print(f"[yellow]No bcrypt hashes detected in {target}. Auditing as plaintext passwords...[/yellow]")
            _audit_plaintext_file(raw_lines, output)
            return
    elif is_bcrypt_hash(target_str):
        target_hashes.append(target_str)
    else:
        console.print(f"[red]Error: Target '{target_str}' is neither an existing file nor a valid bcrypt hash.[/red]")
        raise typer.Exit(code=1)

    # Validate wordlist
    if not wordlist:
        # Check if default sample words exist
        default_sample = Path("data/samplewords.txt")
        if default_sample.exists():
            wordlist = default_sample
            console.print(f"[dim]No --wordlist specified. Using default: {wordlist}[/dim]")
        else:
            console.print("[red]Error: --wordlist must be provided to audit hashes.[/red]")
            raise typer.Exit(code=1)

    console.print(
        f"[bold cyan]Starting Multi-Core Audit:[/bold cyan] "
        f"[white]{len(target_hashes)} target hashes[/white] | "
        f"[green]{workers} worker cores[/green] | "
        f"[yellow]Wordlist: {wordlist}[/yellow]"
    )

    candidates = _stream_wordlist_candidates(wordlist, use_rules=rules)
    console.print(f"[dim]Prepared {len(candidates):,} candidate variations (rules={'enabled' if rules else 'disabled'}).[/dim]")

    engine = MultiCoreAuditEngine(workers=workers)

    with create_audit_progress() as progress:
        task_id = progress.add_task(
            "Auditing hashes",
            total=len(candidates),
            rate="0.0 H/s",
        )

        def on_progress(checked: int, elapsed: float, rate: float, cracked_map: dict[str, str]) -> None:
            progress.update(
                task_id,
                completed=checked,
                rate=f"{rate:.1f} H/s ({len(cracked_map)}/{len(target_hashes)} cracked)",
            )

        results = engine.audit_hashes(
            target_hashes=target_hashes,
            candidate_words=candidates,
            chunk_size=chunk_size,
            progress_callback=on_progress,
        )

    render_audit_results(results)

    if output:
        output_data = [r.to_dict() for r in results]
        with output.open("w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2)
        console.print(f"[green]Audit report saved to {output}[/green]")

    # Exit with code 1 if any hash was cracked
    any_cracked = any(r.cracked for r in results)
    if any_cracked:
        console.print("[bold red]Audit completed: Compromised hashes identified in wordlist![/bold red]")
        raise typer.Exit(code=1)
    else:
        console.print("[bold green]Audit completed: No target hashes matched the wordlist.[/bold green]")


def _audit_plaintext_file(passwords: list[str], output_path: Optional[Path]) -> None:
    """Batch evaluate plaintext passwords against NIST SP 800-63B and HIBP."""
    reports: list[dict] = []
    for pw in passwords:
        nist = evaluate_password(pw)
        breach = check_password_breached(pw)
        report = PasswordHealthReport(
            password_masked=pw[0] + "*" * max(1, len(pw) - 2) + pw[-1] if len(pw) > 2 else "***",
            nist=nist,
            breach=breach,
            verdict=f"Grade {nist.grade} (Score: {nist.score}/100)",
            summary=f"Length {len(pw)}, Entropy {nist.effective_entropy_bits:.1f} bits",
        )
        reports.append(report.to_dict())
        render_password_health(report)

    if output_path:
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2)
        console.print(f"[green]Health audit saved to {output_path}[/green]")


@app.command(name="benchmark")
def benchmark_command(
    cost: Annotated[
        int,
        typer.Option("--cost", "-c", min=4, max=16, help="Bcrypt cost factor"),
    ] = 10,
    rounds: Annotated[
        int,
        typer.Option("--rounds", "-r", help="Number of benchmark iterations"),
    ] = 16,
    workers: Annotated[
        int,
        typer.Option("--workers", "-w", help="Number of CPU cores to utilize"),
    ] = os.cpu_count() or 1,
) -> None:
    """Benchmark local CPU core performance (single-core vs multi-core throughput)."""
    show_banner()
    console.print(f"[bold cyan]Benchmarking Bcrypt (cost {cost}) across {workers} CPU cores...[/bold cyan]")

    result = run_benchmark(cost_factor=cost, rounds=rounds, workers=workers)
    render_benchmark(result)


@app.command(name="version")
def version_command() -> None:
    """Display Crackerjack version and environment info."""
    show_banner()
    console.print(f"Crackerjack Version: [bold cyan]{__version__}[/bold cyan]")
    console.print(f"Python Runtime: [white]{sys.version.split()[0]}[/white]")
    console.print(f"Available CPU Cores: [bold green]{os.cpu_count() or 1}[/bold green]")
