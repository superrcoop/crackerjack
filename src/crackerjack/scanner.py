"""DevSecOps repository secret scanner detecting weak or breached hardcoded passwords."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Generator, Optional

from crackerjack.auditor import evaluate_password
from crackerjack.models import ScanFinding

# Patterns matching secret and password assignments in code, env files, and configs
SECRET_PATTERNS: list[re.Pattern] = [
    # KEY = "value" or KEY: "value"
    re.compile(
        r"""(?i)(?:[\w.-]*(?:password|passwd|secret|token|auth_pass|db_pass|app_key|credential)[\w.-]*)\s*[:=]\s*["']([^"'#\n]{4,})["']"""
    ),
    # export KEY="value" or ENV KEY="value"
    re.compile(
        r"""(?i)(?:export\s+|ENV\s+)?([A-Z0-9_]*(?:PASSWORD|PASS|SECRET|TOKEN)[A-Z0-9_]*)\s*=\s*["']?([^"'#\s\n]{4,})["']?"""
    ),
]

EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
    "dist", "build", ".idea", ".vscode", ".tox", ".eggs", "site-packages"
}

ALLOWED_EXTENSIONS = {
    ".env", ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml", ".yml",
    ".toml", ".ini", ".conf", ".sh", ".bash", ".zsh", ".dockerfile", ".tf",
    ".sql", ".properties"
}


def _mask_secret(secret: str) -> str:
    """Mask secret displaying only outer characters."""
    if len(secret) <= 3:
        return "***"
    return secret[0] + "*" * (len(secret) - 2) + secret[-1]


def scan_file(file_path: Path, check_breach: bool = False) -> list[ScanFinding]:
    """Scan an individual file for hardcoded secrets and evaluate their strength."""
    findings: list[ScanFinding] = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    lines = content.splitlines()
    for line_idx, line in enumerate(lines, 1):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#") or line_clean.startswith("//"):
            continue

        for pattern in SECRET_PATTERNS:
            matches = pattern.finditer(line)
            for m in matches:
                groups = [g for g in m.groups() if g]
                if not groups:
                    continue

                if len(groups) == 1:
                    var_name = "secret"
                    raw_secret = groups[0]
                else:
                    var_name = groups[0]
                    raw_secret = groups[1]

                raw_secret = raw_secret.strip()
                # Skip template variables like ${DB_PASSWORD} or %PASSWORD%
                if raw_secret.startswith("${") or raw_secret.startswith("$") or raw_secret.startswith("%"):
                    continue

                nist = evaluate_password(raw_secret)
                breached = False
                breach_count = 0

                if check_breach:
                    try:
                        from crackerjack.breach import check_password_breached
                        b = check_password_breached(raw_secret)
                        breached = b.pwned
                        breach_count = b.breach_count
                    except Exception:
                        pass

                findings.append(
                    ScanFinding(
                        file_path=str(file_path),
                        line_number=line_idx,
                        variable_name=var_name,
                        secret_masked=_mask_secret(raw_secret),
                        raw_secret=raw_secret,
                        nist_score=nist.score,
                        nist_grade=nist.grade,
                        breached=breached,
                        breach_count=breach_count,
                    )
                )

    return findings


def scan_directory(
    target_dir: Path,
    check_breach: bool = False,
) -> list[ScanFinding]:
    """Recursively scan a directory tree for hardcoded secrets in code and configuration."""
    all_findings: list[ScanFinding] = []

    for root, dirs, files in os.walk(target_dir):
        # Exclude directories in-place
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS and not d.startswith(".")]

        for fname in files:
            p = Path(root) / fname
            # Check if file has an allowed extension or is a dot-env file
            if p.suffix.lower() in ALLOWED_EXTENSIONS or fname.startswith(".env"):
                file_findings = scan_file(p, check_breach=check_breach)
                all_findings.extend(file_findings)

    return all_findings
