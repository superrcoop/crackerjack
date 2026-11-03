"""Structured credential dump parsers for Linux shadow, Windows NTDS, and CSV formats."""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Optional, Union

from crackerjack.engine import detect_hash_type
from crackerjack.models import TargetCredential


def extract_identity_context_terms(identity: str, email: Optional[str] = None) -> list[str]:
    """Extract context terms (username, name parts, email prefix, domain) from an identity."""
    terms: set[str] = set()

    for raw in [identity, email]:
        if not raw:
            continue
        cleaned = raw.strip().lower()
        if not cleaned:
            continue

        # If it looks like an email or domain
        if "@" in cleaned:
            user_part, domain_part = cleaned.split("@", 1)
            terms.add(cleaned)
            terms.add(user_part)
            # Add company domain name (e.g. acme from acme.com)
            domain_name = domain_part.split(".")[0]
            if len(domain_name) >= 3:
                terms.add(domain_name)
            cleaned = user_part

        terms.add(cleaned)
        # Split on common separators (dots, underscores, dashes)
        sub_tokens = re.split(r"[._\-+]+", cleaned)
        for token in sub_tokens:
            if len(token) >= 3:
                terms.add(token)

    return sorted([t for t in terms if len(t) >= 3])


def parse_shadow_file(source: Union[Path, list[str]]) -> list[TargetCredential]:
    """Parse a Linux /etc/shadow credential file into TargetCredential objects."""
    lines: list[str] = []
    if isinstance(source, Path):
        lines = source.read_text(encoding="utf-8", errors="ignore").splitlines()
    else:
        lines = source

    credentials: list[TargetCredential] = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(":")
        if len(parts) < 2:
            continue

        username = parts[0].strip()
        hash_val = parts[1].strip()

        # Skip disabled or locked accounts (*, !, !!, or locked prefix)
        if not hash_val or hash_val in ("*", "!", "!!", "x"):
            continue
        if hash_val.startswith("!") or hash_val.startswith("*"):
            continue

        algo = detect_hash_type(hash_val)
        if algo == "unknown":
            # Check for standard crypt formats: $6$ (SHA-512), $5$ (SHA-256), $1$ (MD5), $y$ (yescrypt)
            if hash_val.startswith("$6$"):
                algo = "sha512crypt"
            elif hash_val.startswith("$5$"):
                algo = "sha256crypt"
            elif hash_val.startswith("$1$"):
                algo = "md5crypt"
            elif hash_val.startswith("$y$"):
                algo = "yescrypt"

        context_terms = extract_identity_context_terms(username)

        credentials.append(
            TargetCredential(
                identity=username,
                hash_val=hash_val,
                hash_type=algo,
                context_terms=context_terms,
            )
        )

    return credentials


def parse_ntds_file(source: Union[Path, list[str]]) -> list[TargetCredential]:
    """Parse Windows Active Directory NTDS.dit / secretsdump extract."""
    lines: list[str] = []
    if isinstance(source, Path):
        lines = source.read_text(encoding="utf-8", errors="ignore").splitlines()
    else:
        lines = source

    credentials: list[TargetCredential] = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(":")
        # secretsdump format: Username:RID:LM-hash:NTLM-hash:::
        if len(parts) >= 4:
            username = parts[0].strip()
            ntlm_hash = parts[3].strip()
            # Valid NTLM hash is 32 hex characters
            if len(ntlm_hash) == 32 and all(c in "0123456789abcdefABCDEF" for c in ntlm_hash):
                credentials.append(
                    TargetCredential(
                        identity=username,
                        hash_val=ntlm_hash,
                        hash_type="ntlm",
                        context_terms=extract_identity_context_terms(username),
                    )
                )

    return credentials


def parse_csv_file(
    path: Path,
    user_col: str = "username",
    hash_col: str = "hash",
    context_cols: Optional[list[str]] = None,
) -> list[TargetCredential]:
    """Parse CSV user credential dump with configurable column mapping."""
    credentials: list[TargetCredential] = []

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return credentials

        # Case-insensitive column matching
        col_map: dict[str, str] = {c.lower(): c for c in reader.fieldnames}
        actual_user_col = col_map.get(user_col.lower(), reader.fieldnames[0])
        actual_hash_col = col_map.get(hash_col.lower())

        if not actual_hash_col:
            # Fallback to column with 'hash' or 'password' in name
            for col in reader.fieldnames:
                if "hash" in col.lower() or "pass" in col.lower():
                    actual_hash_col = col
                    break
            if not actual_hash_col:
                actual_hash_col = reader.fieldnames[-1]

        for row in reader:
            identity = row.get(actual_user_col, "").strip()
            hash_val = row.get(actual_hash_col, "").strip()
            if not hash_val:
                continue

            # Aggregate context terms
            terms = extract_identity_context_terms(identity)
            if context_cols:
                for c in context_cols:
                    val = row.get(col_map.get(c.lower(), c), "")
                    if val:
                        terms.extend(extract_identity_context_terms(val))

            algo = detect_hash_type(hash_val)

            credentials.append(
                TargetCredential(
                    identity=identity or "unknown",
                    hash_val=hash_val,
                    hash_type=algo,
                    context_terms=sorted(list(set(terms))),
                )
            )

    return credentials


def auto_detect_and_parse(
    path: Path,
    format_hint: str = "auto",
    user_col: str = "username",
    hash_col: str = "hash",
) -> list[TargetCredential]:
    """Auto-detect file format and parse into TargetCredential objects."""
    if not path.is_file():
        return []

    hint = format_hint.lower()
    if hint == "shadow":
        return parse_shadow_file(path)
    if hint in ("ntds", "secretsdump"):
        return parse_ntds_file(path)
    if hint == "csv":
        return parse_csv_file(path, user_col=user_col, hash_col=hash_col)

    # Automatic detection based on content
    lines = [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()[:20]
        if line.strip() and not line.startswith("#")
    ]

    if not lines:
        return []

    # Check if CSV
    if path.suffix.lower() == ".csv" or ("," in lines[0] and ("hash" in lines[0].lower() or "user" in lines[0].lower())):
        return parse_csv_file(path, user_col=user_col, hash_col=hash_col)

    # Check if /etc/shadow (typically 8-9 colon-delimited fields, line contains $id$)
    sample = lines[0]
    if sample.count(":") >= 4 and "$" in sample:
        shadow_creds = parse_shadow_file(path)
        if shadow_creds:
            return shadow_creds

    # Check if NTDS (4+ colons, 4th element is 32-char hex)
    if sample.count(":") >= 3:
        ntds_creds = parse_ntds_file(path)
        if ntds_creds:
            return ntds_creds

    # Fallback: Bare hashes or simple user:hash list
    credentials: list[TargetCredential] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if ":" in line:
            parts = line.split(":", 1)
            ident = parts[0].strip()
            h = parts[1].strip()
            algo = detect_hash_type(h)
            if algo != "unknown":
                credentials.append(
                    TargetCredential(
                        identity=ident,
                        hash_val=h,
                        hash_type=algo,
                        context_terms=extract_identity_context_terms(ident),
                    )
                )
                continue

        algo = detect_hash_type(line)
        if algo != "unknown":
            credentials.append(
                TargetCredential(
                    identity="hash",
                    hash_val=line,
                    hash_type=algo,
                    context_terms=[],
                )
            )

    return credentials
