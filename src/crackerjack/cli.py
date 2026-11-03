"""Typer CLI interface for Crackerjack 3.0."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.panel import Panel

from crackerjack import __version__
from crackerjack.auditor import evaluate_password
from crackerjack.breach import check_password_breached
from crackerjack.engine import (
    MultiCoreAuditEngine,
    detect_hash_type,
    hash_password,
    run_benchmark,
)
from crackerjack.generator import generate_passphrase
from crackerjack.honey import generate_honeywords, inject_honey_hash, verify_honeyword
from crackerjack.hygiene import analyze_crypto_hygiene
from crackerjack.ledger import calculate_drift, get_audit_history, record_audit
from crackerjack.models import (
    BreachInfo,
    HashAuditResult,
    HoneywordSet,
    PasswordHealthReport,
    TargetCredential,
)
from crackerjack.mutator import generate_probabilistic_candidates
from crackerjack.parsers import auto_detect_and_parse
from crackerjack.reporter import build_compliance_summary, save_html_report
from crackerjack.scanner import scan_directory, scan_file
from crackerjack.server import run_server
from crackerjack.ui import (
    console,
    create_audit_progress,
    render_audit_results,
    render_benchmark,
    render_crypto_hygiene,
    render_drift_history,
    render_honeyword_set,
    render_passphrase,
    render_password_health,
    render_scan_results,
    show_banner,
)
from crackerjack.webhooks import dispatch_webhook
from crackerjack.wordlist import stream_candidates

app = typer.Typer(
    name="crackerjack",
    help="Crackerjack 3.0: Modern Multi-Core Password Health Auditor & NIST SP 800-63B Compliance Checker",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def main_callback() -> None:
    """Crackerjack 3.0 Security & Audit Suite."""


def _parse_context_terms(context_str: Optional[str]) -> list[str] | None:
    """Parse comma-separated context terms."""
    if not context_str:
        return None
    terms = [t.strip() for t in context_str.split(",") if t.strip()]
    return terms or None


@app.command(name="check")
def check_command(
    password: Annotated[
        Optional[str],
        typer.Argument(help="Plaintext password to evaluate (prompted securely if omitted)"),
    ] = None,
    context: Annotated[
        Optional[str],
        typer.Option(
            "--context",
            "-C",
            help="Comma-separated context terms (username, applicant name, service, company) per NIST SP 800-63B",
        ),
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

    context_terms = _parse_context_terms(context)
    nist_eval = evaluate_password(password, context_terms=context_terms)

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

    masked = (
        password
        if show_plaintext
        else (password[0] + "*" * (len(password) - 2) + password[-1] if len(password) > 2 else "***")
    )

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
        typer.Argument(help="Plaintext password to hash (prompted securely if omitted)"),
    ] = None,
    algo: Annotated[
        str,
        typer.Option(
            "--algo",
            "-a",
            help="Cryptographic hashing algorithm: bcrypt, argon2id, or pbkdf2-sha256",
        ),
    ] = "bcrypt",
    cost: Annotated[
        Optional[int],
        typer.Option(
            "--cost",
            "-c",
            help="Cost factor (rounds for bcrypt, time_cost for argon2, iterations for pbkdf2)",
        ),
    ] = None,
) -> None:
    """Generate a cryptographically secure hash (Bcrypt, Argon2id, or PBKDF2)."""
    if not password:
        password = typer.prompt("Enter password to hash", hide_input=True)

    try:
        hash_str = hash_password(password, algorithm=algo, cost=cost)
        console.print(f"[bold green]{algo.upper()} Hash:[/bold green] [bold white]{hash_str}[/bold white]")
    except Exception as e:
        console.print(f"[bold red]Error generating hash:[/bold red] {e}")
        raise typer.Exit(code=1)


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
            help="Path to dictionary wordlist (supports .txt, .gz, .bz2, .xz)",
        ),
    ] = None,
    context: Annotated[
        Optional[str],
        typer.Option(
            "--context",
            "-C",
            help="Context terms for plaintext evaluations (username, company, service)",
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
    report: Annotated[
        Optional[Path],
        typer.Option("--report", "-r", help="Path to generate standalone executive HTML compliance report"),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Credential dump format (auto, shadow, ntds, csv, hash)"),
    ] = "auto",
    webhook: Annotated[
        Optional[str],
        typer.Option("--webhook", help="SIEM or ChatOps webhook URL (Slack, MS Teams, Generic JSON)"),
    ] = None,
    webhook_format: Annotated[
        str,
        typer.Option("--webhook-format", help="Webhook payload format (generic, slack, teams)"),
    ] = "generic",
    track_history: Annotated[
        bool,
        typer.Option("--track-history/--no-track-history", help="Record audit snapshot to SQLite ledger for drift analysis"),
    ] = False,
    smart_mutations: Annotated[
        bool,
        typer.Option("--smart-mutations/--no-smart-mutations", help="Prioritize probabilistic, context-aware mutations before dictionary scan"),
    ] = False,
) -> None:
    """Audit hashes or passwords using multi-core multiprocessing and streaming wordlists."""
    show_banner()

    target_str = str(target)
    target_hashes: list[str] = []
    cred_map: dict[str, TargetCredential] = {}

    if Path(target).is_file():
        parsed_creds = auto_detect_and_parse(Path(target), format_hint=format)
        for c in parsed_creds:
            if c.hash_type in ("bcrypt", "argon2", "pbkdf2"):
                target_hashes.append(c.hash_val)
                cred_map[c.hash_val] = c

        if not target_hashes:
            raw_lines = _load_lines_from_path(Path(target))
            console.print(f"[yellow]No supported hashes detected in {target}. Auditing as plaintext passwords...[/yellow]")
            context_terms = _parse_context_terms(context)
            _audit_plaintext_file(raw_lines, output, report_path=report, context_terms=context_terms)
            return
    elif detect_hash_type(target_str) != "unknown":
        target_hashes.append(target_str)
        cred_map[target_str] = TargetCredential(identity="cli_target", hash_val=target_str, hash_type=detect_hash_type(target_str))
    else:
        console.print(
            f"[red]Error: Target '{target_str}' is neither an existing file nor a supported hash "
            f"(bcrypt, argon2id, pbkdf2-sha256).[/red]"
        )
        raise typer.Exit(code=1)

    # Validate wordlist
    if not wordlist:
        default_sample = Path("data/samplewords.txt")
        if default_sample.exists():
            wordlist = default_sample
            console.print(f"[dim]No --wordlist specified. Using default: {wordlist}[/dim]")
        else:
            console.print("[red]Error: --wordlist must be provided to audit hashes.[/red]")
            raise typer.Exit(code=1)

    if not wordlist.exists():
        console.print(f"[red]Error: Wordlist not found: {wordlist}[/red]")
        raise typer.Exit(code=1)

    console.print(
        f"[bold cyan]Starting Multi-Core Audit:[/bold cyan] "
        f"[white]{len(target_hashes)} target hashes[/white] | "
        f"[green]{workers} worker cores[/green] | "
        f"[yellow]Wordlist: {wordlist}[/yellow]"
    )

    # Zero-RAM streaming candidate generator
    candidate_stream = stream_candidates(wordlist, use_rules=rules)
    if smart_mutations:
        import itertools
        all_context_terms = list(_parse_context_terms(context) or [])
        for c in cred_map.values():
            all_context_terms.extend(c.context_terms)
        smart_cands = generate_probabilistic_candidates(
            base_words=["Password", "Admin", "Welcome"],
            context_terms=all_context_terms,
            max_candidates=1500,
        )
        candidate_stream = itertools.chain(smart_cands, candidate_stream)
        console.print("[bold cyan]Smart Mutations:[/bold cyan] Prioritizing context-aware probabilistic variations.")

    console.print(f"[dim]Streaming candidate words (rules={'enabled' if rules else 'disabled'}).[/dim]")

    engine = MultiCoreAuditEngine(workers=workers)

    with create_audit_progress() as progress:
        task_id = progress.add_task(
            "Auditing hashes",
            total=None,
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
            candidate_words=candidate_stream,
            chunk_size=chunk_size,
            progress_callback=on_progress,
        )

    render_audit_results(results)

    if output:
        output_data = [r.to_dict() for r in results]
        with output.open("w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2)
        console.print(f"[green]Audit report saved to {output}[/green]")

    if report or track_history or webhook:
        findings: list[dict] = []
        for r in results:
            cred = cred_map.get(r.target_hash)
            ident = cred.identity if cred else "hash"
            c_terms = cred.context_terms if cred else _parse_context_terms(context)

            if r.cracked and r.plaintext:
                nist = evaluate_password(r.plaintext, context_terms=c_terms)
                violations = list(nist.matched_context_terms) if nist.has_context_words else []
                if not nist.passed_min_length:
                    violations.append("Length < 8 chars")
                if nist.is_dictionary_word:
                    violations.append("Dictionary word root")
                findings.append({
                    "identity": ident,
                    "masked": r.plaintext[0] + "*" * max(1, len(r.plaintext) - 2) + r.plaintext[-1] if len(r.plaintext) > 2 else "***",
                    "algorithm": r.hash_type,
                    "verdict": "CRACKED (COMPROMISED)",
                    "score": nist.score,
                    "grade": nist.grade,
                    "violations": violations,
                    "cracked": True,
                    "breached": False,
                })
            else:
                findings.append({
                    "identity": ident,
                    "masked": r.target_hash[:16] + "...",
                    "algorithm": r.hash_type,
                    "verdict": "SECURE (UNCRACKED)",
                    "score": 90,
                    "grade": "A",
                    "violations": [],
                    "cracked": False,
                    "breached": False,
                })

        summary = build_compliance_summary(findings)

        history_entries = None
        if track_history:
            entry = record_audit(summary, target_name=str(target))
            console.print(f"[bold cyan]Snapshot recorded to audit ledger (Run #{entry.entry_id}, Score: {entry.overall_score}/100)[/bold cyan]")
            history_entries = get_audit_history(limit=20)
        else:
            existing = get_audit_history(limit=20)
            if len(existing) >= 2:
                history_entries = existing

        hygiene_rep = analyze_crypto_hygiene(list(cred_map.values()) if cred_map else target_hashes)

        if report:
            save_html_report(
                summary,
                report,
                title="Executive Credential Audit & Compliance Report",
                history=history_entries,
                hygiene_report=hygiene_rep,
            )
            console.print(f"[bold green]Executive HTML compliance report saved to {report}[/bold green]")

        if webhook:
            notif = dispatch_webhook(webhook, "audit_completed", summary.to_dict(), format_type=webhook_format)
            if notif.success:
                console.print(f"[bold green]SIEM / Webhook alert successfully dispatched to {webhook}[/bold green]")
            else:
                console.print(f"[yellow]Webhook alert dispatch failed: {notif.error_message}[/yellow]")

    any_cracked = any(r.cracked for r in results)
    if any_cracked:
        console.print("[bold red]Audit completed: Compromised hashes identified in wordlist![/bold red]")
        raise typer.Exit(code=1)
    else:
        console.print("[bold green]Audit completed: No target hashes matched the wordlist.[/bold green]")


def _audit_plaintext_file(
    passwords: list[str],
    output_path: Optional[Path],
    report_path: Optional[Path] = None,
    context_terms: list[str] | None = None,
    track_history: bool = False,
    webhook: Optional[str] = None,
    webhook_format: str = "generic",
) -> None:
    """Batch evaluate plaintext passwords against NIST SP 800-63B and HIBP."""
    reports: list[dict] = []
    findings: list[dict] = []

    for idx, pw in enumerate(passwords, 1):
        nist = evaluate_password(pw, context_terms=context_terms)
        breach = check_password_breached(pw)
        masked = pw[0] + "*" * max(1, len(pw) - 2) + pw[-1] if len(pw) > 2 else "***"
        report = PasswordHealthReport(
            password_masked=masked,
            nist=nist,
            breach=breach,
            verdict=f"Grade {nist.grade} (Score: {nist.score}/100)",
            summary=f"Length {len(pw)}, Entropy {nist.effective_entropy_bits:.1f} bits",
        )
        reports.append(report.to_dict())
        render_password_health(report)

        violations = list(nist.matched_context_terms) if nist.has_context_words else []
        if not nist.passed_min_length:
            violations.append("Length < 8 chars")
        if breach.pwned:
            violations.append(f"Breached in {breach.breach_count:,} dumps")

        findings.append({
            "identity": f"password_{idx}",
            "masked": masked,
            "algorithm": "PLAINTEXT",
            "verdict": "BREACHED" if breach.pwned else f"Grade {nist.grade}",
            "score": nist.score,
            "grade": nist.grade,
            "violations": violations,
            "cracked": False,
            "breached": breach.pwned,
        })

    if output_path:
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2)
        console.print(f"[green]Health audit saved to {output_path}[/green]")

    if report_path or track_history or webhook:
        summary = build_compliance_summary(findings)
        history_entries = None
        if track_history:
            entry = record_audit(summary, target_name="plaintext_batch")
            console.print(f"[bold cyan]Snapshot recorded to audit ledger (Run #{entry.entry_id}, Score: {entry.overall_score}/100)[/bold cyan]")
            history_entries = get_audit_history(limit=20)
        else:
            existing = get_audit_history(limit=20)
            if len(existing) >= 2:
                history_entries = existing

        if report_path:
            save_html_report(
                summary,
                report_path,
                title="Plaintext Password Governance Report",
                history=history_entries,
            )
            console.print(f"[bold green]Executive HTML compliance report saved to {report_path}[/bold green]")

        if webhook:
            notif = dispatch_webhook(webhook, "audit_completed", summary.to_dict(), format_type=webhook_format)
            if notif.success:
                console.print(f"[bold green]SIEM / Webhook alert successfully dispatched to {webhook}[/bold green]")
            else:
                console.print(f"[yellow]Webhook alert dispatch failed: {notif.error_message}[/yellow]")


@app.command(name="benchmark")
def benchmark_command(
    algo: Annotated[
        str,
        typer.Option("--algo", "-a", help="Algorithm: bcrypt, argon2id, or pbkdf2-sha256"),
    ] = "bcrypt",
    cost: Annotated[
        Optional[int],
        typer.Option("--cost", "-c", help="Cost factor / work rounds / iterations"),
    ] = None,
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
    console.print(f"[bold cyan]Benchmarking {algo.upper()} across {workers} CPU cores...[/bold cyan]")

    result = run_benchmark(
        algorithm=algo,
        cost_factor=cost,
        rounds=rounds,
        workers=workers,
    )
    render_benchmark(result)


@app.command(name="version")
def version_command() -> None:
    """Display Crackerjack version and environment info."""
    show_banner()
    console.print(f"Crackerjack Version: [bold cyan]{__version__}[/bold cyan]")
    console.print(f"Python Runtime: [white]{sys.version.split()[0]}[/white]")
    console.print(f"Available CPU Cores: [bold green]{os.cpu_count() or 1}[/bold green]")


@app.command(name="generate")
def generate_command(
    words: Annotated[
        int,
        typer.Option("--words", "-w", help="Number of distinct words in passphrase (3 to 12)"),
    ] = 4,
    separator: Annotated[
        str,
        typer.Option("--separator", "-s", help="Separator delimiter between words"),
    ] = "-",
    capitalize: Annotated[
        bool,
        typer.Option("--capitalize", "-c", help="Capitalize each word in passphrase"),
    ] = False,
    number: Annotated[
        bool,
        typer.Option("--number/--no-number", "-n", help="Append random 3-digit number"),
    ] = True,
    symbol: Annotated[
        bool,
        typer.Option("--symbol/--no-symbol", help="Append random symbol"),
    ] = False,
    check_breach: Annotated[
        bool,
        typer.Option("--check-breach/--no-breach", help="Verify generated passphrase against HaveIBeenPwned"),
    ] = True,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output result in JSON format"),
    ] = False,
) -> None:
    """Generate a cryptographically secure, NIST SP 800-63B compliant multi-word passphrase."""
    res = generate_passphrase(
        word_count=words,
        separator=separator,
        capitalize=capitalize,
        add_number=number,
        add_symbol=symbol,
        check_breach=check_breach,
    )

    if json_output:
        console.print(json.dumps(res.to_dict(), indent=2))
    else:
        render_passphrase(res)


@app.command(name="serve")
def serve_command(
    host: Annotated[
        str,
        typer.Option("--host", "-h", help="Host address to bind the API server"),
    ] = "0.0.0.0",
    port: Annotated[
        int,
        typer.Option("--port", "-p", help="Port to listen on"),
    ] = 8000,
) -> None:
    """Start the Crackerjack REST API microservice for real-time validation and scoring."""
    show_banner()
    run_server(host=host, port=port)


@app.command(name="scan")
def scan_command(
    target: Annotated[
        Path,
        typer.Argument(help="File or directory path to scan for hardcoded secrets"),
    ] = Path("."),
    fail_under: Annotated[
        int,
        typer.Option("--fail-under", help="Exit code 1 if any secret has a NIST score below this"),
    ] = 70,
    fail_on_breached: Annotated[
        bool,
        typer.Option("--fail-on-breached/--ignore-breached", help="Exit code 1 if any secret is in a breach"),
    ] = True,
    check_breach: Annotated[
        bool,
        typer.Option("--check-breach/--no-breach", help="Check detected secrets against HaveIBeenPwned API"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output scan findings in JSON format"),
    ] = False,
    webhook: Annotated[
        Optional[str],
        typer.Option("--webhook", help="SIEM or ChatOps webhook URL to alert if secrets are found"),
    ] = None,
    webhook_format: Annotated[
        str,
        typer.Option("--webhook-format", help="Webhook payload format (generic, slack, teams)"),
    ] = "generic",
) -> None:
    """Scan files or repository trees for exposed, weak, or breached credentials in code and configs."""
    target_path = Path(target)
    if not target_path.exists():
        console.print(f"[red]Error: Target path does not exist: {target_path}[/red]")
        raise typer.Exit(code=1)

    if target_path.is_file():
        findings = scan_file(target_path, check_breach=check_breach)
    else:
        findings = scan_directory(target_path, check_breach=check_breach)

    if json_output:
        console.print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        render_scan_results(findings)

    if findings and webhook:
        notif = dispatch_webhook(
            webhook,
            "secret_detected",
            {
                "findings_count": len(findings),
                "files": list(set(f.file_path for f in findings)),
                "breached_count": sum(1 for f in findings if f.breached),
            },
            format_type=webhook_format,
        )
        if notif.success:
            console.print(f"[bold green]SIEM / Webhook alert successfully dispatched to {webhook}[/bold green]")
        else:
            console.print(f"[yellow]Webhook alert dispatch failed: {notif.error_message}[/yellow]")

    # Check failure conditions
    has_low_score = any(f.nist_score < fail_under for f in findings)
    has_breached = any(f.breached for f in findings)

    if has_breached and fail_on_breached:
        console.print(f"[bold red]CI Gate Failure: Known breached credentials detected in {target_path}![/bold red]")
        raise typer.Exit(code=1)
    elif has_low_score:
        console.print(f"[bold red]CI Gate Failure: Credentials scoring below threshold ({fail_under}/100) detected![/bold red]")
        raise typer.Exit(code=1)
    elif findings:
        console.print(f"[yellow]Scan completed: {len(findings)} secrets detected (passed thresholds).[/yellow]")
    else:
        console.print("[green]Scan completed: No secrets detected.[/green]")


@app.command(name="drift")
@app.command(name="history")
def drift_command(
    limit: Annotated[int, typer.Option("--limit", "-n", help="Number of historical runs to display")] = 10,
    db: Annotated[Optional[Path], typer.Option("--db", help="Path to custom SQLite ledger database")] = None,
) -> None:
    """Display continuous compliance drift and health score progression across audit runs."""
    show_banner()
    drift = calculate_drift(db_path=db)
    render_drift_history(drift)


@app.command(name="hygiene")
def hygiene_command(
    target: Annotated[Path, typer.Argument(help="Path to credential dump, shadow, NTDS, or hash list file")],
    format: Annotated[str, typer.Option("--format", "-f", help="Format hint (auto, shadow, ntds, csv, hash)")] = "auto",
) -> None:
    """Assess cryptographic hygiene, detect deprecated KDF algorithms, and evaluate GPU attack resistance."""
    show_banner()
    if not target.exists():
        console.print(f"[red]Error: Target file not found: {target}[/red]")
        raise typer.Exit(code=1)

    creds = auto_detect_and_parse(target, format_hint=format)
    if not creds:
        raw_lines = _load_lines_from_path(target)
        creds = [
            TargetCredential(identity=f"hash_{i}", hash_val=line, hash_type=detect_hash_type(line))
            for i, line in enumerate(raw_lines, 1)
        ]

    report = analyze_crypto_hygiene(creds)
    render_crypto_hygiene(report)


@app.command(name="mutate")
def mutate_command(
    words: Annotated[str, typer.Option("--words", "-w", help="Comma-separated base dictionary words")] = "Password,Admin,Welcome",
    context: Annotated[Optional[str], typer.Option("--context", "-C", help="Context terms (organization, department, names)")] = None,
    count: Annotated[int, typer.Option("--count", "-c", help="Number of probabilistic candidates to generate")] = 100,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Save generated candidates to a file")] = None,
) -> None:
    """Generate high-probability password candidates matching real-world human mutation patterns."""
    show_banner()
    base_words = [w.strip() for w in words.split(",") if w.strip()]
    ctx_terms = _parse_context_terms(context)

    candidates = list(generate_probabilistic_candidates(base_words, context_terms=ctx_terms, max_candidates=count))
    console.print(f"[bold cyan]Generated {len(candidates)} Probabilistic Candidates:[/bold cyan]")
    for c in candidates[:20]:
        console.print(f"  • [green]{c}[/green]")
    if len(candidates) > 20:
        console.print(f"  [dim]... and {len(candidates) - 20} more candidates[/dim]")

    if output:
        output.write_text("\n".join(candidates) + "\n", encoding="utf-8")
        console.print(f"[bold green]Candidates saved to {output}[/bold green]")


honey_app = typer.Typer(name="honey", help="Active Cyber Deception: Honeywords & Canary Tripwires")


@honey_app.command(name="generate")
def honey_generate(
    password: Annotated[str, typer.Option("--password", "-p", help="Real password for which to generate decoys", prompt=True, hide_input=True)],
    count: Annotated[int, typer.Option("--count", "-c", help="Total honeyword count (real password + decoys)")] = 5,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Save HoneywordSet to JSON file for tripwire monitoring")] = None,
) -> None:
    """Generate indistinguishable honeywords matching the real password's character pool and entropy."""
    hset = generate_honeywords(password, count=count)
    render_honeyword_set(hset)
    if output:
        with output.open("w", encoding="utf-8") as f:
            json.dump(hset.to_dict(), f, indent=2)
        console.print(f"[bold green]HoneywordSet tripwire definition saved to {output}[/bold green]")


@honey_app.command(name="inject")
def honey_inject(
    target_type: Annotated[str, typer.Option("--type", "-t", help="Target credential store: shadow, ntds, or sql")] = "shadow",
    identity: Annotated[str, typer.Option("--identity", "-u", help="Decoy username or service account")] = "admin_backup",
    hash_val: Annotated[str, typer.Option("--hash", "-H", help="Canary hash string to inject")] = "$2b$12$e8POdGlHFgqWq7GfQ1L46.kIeD5W3hF9qgJ4z7r0u6t5g8v9k3y5e",
    canary_tag: Annotated[Optional[str], typer.Option("--canary", help="Optional custom canary identifier")] = None,
) -> None:
    """Format a canary honey-hash entry for injection into shadow files, Active Directory, or SQL tables."""
    formatted = inject_honey_hash(target_type, identity, hash_val, canary_tag=canary_tag)
    console.print(Panel(formatted, title=f"[bold cyan]Decoy {target_type.upper()} Record[/bold cyan]", border_style="cyan"))


@honey_app.command(name="verify")
def honey_verify(
    input_password: Annotated[str, typer.Option("--input", "-i", help="Candidate password to verify against honeywords", prompt=True, hide_input=True)],
    file: Annotated[Path, typer.Option("--file", "-f", help="Path to HoneywordSet JSON file")],
    webhook: Annotated[Optional[str], typer.Option("--webhook", help="SIEM webhook URL to alert if canary tripped")] = None,
) -> None:
    """Tripwire verification: Check if an authentication attempt used a decoy honeyword."""
    if not file.exists():
        console.print(f"[red]Error: Honeyword file not found: {file}[/red]")
        raise typer.Exit(code=1)

    with file.open("r", encoding="utf-8") as f:
        data = json.load(f)

    hset = HoneywordSet(
        real_password=data["real_password"],
        honeywords=data["honeywords"],
        real_index=data["real_index"],
        decoy_count=data["decoy_count"],
        avg_entropy_bits=data["avg_entropy_bits"],
        canary_tag=data["canary_tag"],
    )

    result = verify_honeyword(input_password, hset)
    if result["tripped_canary"]:
        console.print(Panel(result["message"], title="[bold red]CANARY TRIPWIRE ALARM[/bold red]", border_style="red"))
        if webhook:
            dispatch_webhook(
                webhook,
                "honeyword_tripped",
                {"canary_tag": hset.canary_tag, "tripped_credential": input_password},
            )
        raise typer.Exit(code=2)
    elif result["authenticated"]:
        console.print("[bold green]Success:[/bold green] Authentic credential verified.")
    else:
        console.print("[yellow]Notice:[/yellow] Incorrect password submitted.")


app.add_typer(honey_app, name="honey")

