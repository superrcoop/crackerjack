"""Tests for Typer CLI commands."""

import gzip
from pathlib import Path
from unittest.mock import patch

import bcrypt
from crackerjack.cli import app
from crackerjack.models import BreachInfo
from typer.testing import CliRunner

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Crackerjack Version" in result.output
    assert "3.3.0" in result.output


def test_cli_hash_bcrypt():
    result = runner.invoke(app, ["hash", "MySecretPassword123!", "--cost", "4"])
    assert result.exit_code == 0
    assert "BCRYPT Hash" in result.output
    assert "$2b$04$" in result.output


def test_cli_hash_pbkdf2():
    result = runner.invoke(app, ["hash", "MySecretPassword123!", "--algo", "pbkdf2-sha256", "--cost", "1000"])
    assert result.exit_code == 0
    assert "PBKDF2-SHA256 Hash" in result.output
    assert "$pbkdf2-sha256$1000$" in result.output


@patch("crackerjack.cli.check_password_breached")
def test_cli_check_safe(mock_breach):
    mock_breach.return_value = BreachInfo(
        pwned=False,
        breach_count=0,
        status_message="Safe",
    )
    result = runner.invoke(app, ["check", "Correct-Horse-Battery-Staple-2026!"])
    assert result.exit_code == 0
    assert "EXCELLENT" in result.output or "STRONG" in result.output


@patch("crackerjack.cli.check_password_breached")
def test_cli_check_with_context_penalty(mock_breach):
    mock_breach.return_value = BreachInfo(
        pwned=False,
        breach_count=0,
        status_message="Safe",
    )
    result = runner.invoke(app, ["check", "AcmeCorpPassphrase2026!", "--context", "acme,admin"])
    assert result.exit_code == 0
    assert "Context-Specific Match" in result.output
    assert "acme" in result.output


@patch("crackerjack.cli.check_password_breached")
def test_cli_check_breached_fails(mock_breach):
    mock_breach.return_value = BreachInfo(
        pwned=True,
        breach_count=50000,
        status_message="CRITICAL: Found in 50,000 known data breaches!",
    )
    result = runner.invoke(app, ["check", "password123"])
    assert result.exit_code == 1
    assert "COMPROMISED" in result.output or "CRITICAL" in result.output


def test_cli_audit_command_gzip_wordlist(tmp_path: Path):
    pw = "sampleword123"
    hashed = bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(rounds=4)).decode("ascii")

    hash_file = tmp_path / "test_hashes.txt"
    hash_file.write_text(f"{hashed}\n")

    # Write wordlist as a .gz compressed file
    wordlist_gz = tmp_path / "test_words.txt.gz"
    with gzip.open(wordlist_gz, "wb") as f:
        f.write(b"dummy1\nsampleword123\ndummy2\n")

    output_json = tmp_path / "result.json"

    result = runner.invoke(
        app,
        [
            "audit",
            str(hash_file),
            "--wordlist",
            str(wordlist_gz),
            "--workers",
            "2",
            "--no-rules",
            "--output",
            str(output_json),
        ],
    )
    assert result.exit_code == 1
    assert "CRACKED" in result.output
    assert output_json.exists()


def test_cli_generate_command():
    result = runner.invoke(app, ["generate", "--words", "4", "--separator", "-", "--no-breach"])
    assert result.exit_code == 0
    assert "Certified Passphrase" in result.output
    assert "Theoretical Entropy" in result.output


def test_cli_scan_command_clean(tmp_path: Path):
    clean_file = tmp_path / "main.py"
    clean_file.write_text("print('hello world')\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "No hardcoded passwords or weak secrets detected" in result.output


def test_cli_audit_with_html_report(tmp_path: Path):
    pw = "mysecret123"
    hashed = bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(rounds=4)).decode("ascii")

    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text(f"sysadmin:{hashed}\n")

    dict_file = tmp_path / "dict.txt"
    dict_file.write_text("mysecret123\n")

    report_html = tmp_path / "report.html"

    result = runner.invoke(
        app,
        [
            "audit",
            str(hash_file),
            "--wordlist",
            str(dict_file),
            "--workers",
            "1",
            "--no-rules",
            "--report",
            str(report_html),
        ],
    )
    assert report_html.exists()
    assert "<!DOCTYPE html>" in report_html.read_text(encoding="utf-8")


def test_cli_drift_command():
    result = runner.invoke(app, ["drift"])
    assert result.exit_code == 0
    assert "Compliance Drift" in result.output or "No historical audits" in result.output


def test_cli_mutate_command():
    result = runner.invoke(app, ["mutate", "--words", "Acme", "--count", "15"])
    assert result.exit_code == 0
    assert "Probabilistic Candidates" in result.output
    assert "Acme" in result.output


def test_cli_honey_generate_and_inject():
    # Test honey inject
    res_inject = runner.invoke(app, ["honey", "inject", "--type", "shadow", "--identity", "test_canary"])
    assert res_inject.exit_code == 0
    assert "test_canary" in res_inject.output
    assert "cj-canary" in res_inject.output


def test_cli_hygiene_command(tmp_path: Path):
    hashes_file = tmp_path / "dump.txt"
    hashes_file.write_text("user1:$2b$12$e8POdGlHFgqWq7GfQ1L46.kIeD5W3hF9qgJ4z7r0u6t5g8v9k3y5e\nuser2:31d6cfe0d16ae931b73c59d7e0c089c0\n")

    result = runner.invoke(app, ["hygiene", str(hashes_file)])
    assert result.exit_code == 0
    assert "Cryptographic Posture" in result.output
    assert "NTLM" in result.output


