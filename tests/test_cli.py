"""Tests for Typer CLI commands."""

from pathlib import Path
from unittest.mock import patch

import bcrypt
import pytest
from crackerjack.cli import app
from crackerjack.models import BreachInfo
from typer.testing import CliRunner

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Crackerjack Version" in result.output
    assert "3.0.0" in result.output


def test_cli_hash():
    result = runner.invoke(app, ["hash", "MySecretPassword123!", "--cost", "4"])
    assert result.exit_code == 0
    assert "Bcrypt Hash" in result.output
    assert "$2b$04$" in result.output


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
def test_cli_check_breached_fails(mock_breach):
    mock_breach.return_value = BreachInfo(
        pwned=True,
        breach_count=50000,
        status_message="CRITICAL: Found in 50,000 known data breaches!",
    )
    result = runner.invoke(app, ["check", "password123"])
    assert result.exit_code == 1
    assert "COMPROMISED" in result.output or "CRITICAL" in result.output


def test_cli_audit_command(tmp_path: Path):
    pw = "sampleword123"
    hashed = bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(rounds=4)).decode("ascii")

    hash_file = tmp_path / "test_hashes.txt"
    hash_file.write_text(f"{hashed}\n")

    wordlist_file = tmp_path / "test_words.txt"
    wordlist_file.write_text("dummy1\nsampleword123\ndummy2\n")

    output_json = tmp_path / "result.json"

    result = runner.invoke(
        app,
        [
            "audit",
            str(hash_file),
            "--wordlist",
            str(wordlist_file),
            "--workers",
            "2",
            "--no-rules",
            "--output",
            str(output_json),
        ],
    )
    # Since a hash was cracked, exit code is 1 (alerting security admins)
    assert result.exit_code == 1
    assert "CRACKED" in result.output
    assert output_json.exists()
