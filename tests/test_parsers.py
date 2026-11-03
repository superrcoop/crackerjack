"""Tests for structured credential dump parsers (Linux shadow, NTDS, CSV)."""

from pathlib import Path

from crackerjack.parsers import (
    auto_detect_and_parse,
    extract_identity_context_terms,
    parse_csv_file,
    parse_ntds_file,
    parse_shadow_file,
)


def test_extract_identity_context_terms():
    # User email
    terms = extract_identity_context_terms("john.doe@acmecorp.com")
    assert "john.doe" in terms
    assert "john" in terms
    assert "doe" in terms
    assert "acmecorp" in terms

    # Simple username with separator
    terms_user = extract_identity_context_terms("admin_backup")
    assert "admin" in terms_user
    assert "backup" in terms_user


def test_parse_shadow_file(tmp_path: Path):
    shadow_content = (
        "root:$6$rounds=5000$saltsalt$fakehash123:19000:0:99999:7:::\n"
        "bin:*:19000:0:99999:7:::\n"  # Locked, skip
        "daemon:!:19000:0:99999:7:::\n"  # Locked, skip
        "alice:$2b$12$e8POdGlHFgqWq7GfQ1L46.kIeD5W3hF9qgJ4z7r0u6t5g8v9k3y5e:19000:0:99999:7:::\n"
    )
    shadow_file = tmp_path / "shadow"
    shadow_file.write_text(shadow_content, encoding="utf-8")

    creds = parse_shadow_file(shadow_file)
    assert len(creds) == 2

    c_root = next(c for c in creds if c.identity == "root")
    assert c_root.hash_type == "sha512crypt"
    assert "root" in c_root.context_terms

    c_alice = next(c for c in creds if c.identity == "alice")
    assert c_alice.hash_type == "bcrypt"
    assert "alice" in c_alice.context_terms


def test_parse_ntds_file(tmp_path: Path):
    ntds_content = (
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        "Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
    )
    ntds_file = tmp_path / "ntds.dit"
    ntds_file.write_text(ntds_content, encoding="utf-8")

    creds = parse_ntds_file(ntds_file)
    assert len(creds) == 2
    assert creds[0].identity == "Administrator"
    assert creds[0].hash_type == "ntlm"
    assert creds[0].hash_val == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_parse_csv_file(tmp_path: Path):
    csv_content = (
        "user_email,full_name,password_hash\n"
        "bob@company.com,Bob Smith,$2b$04$fakehashbob\n"
        "carol@company.com,Carol Davis,$pbkdf2-sha256$1000$c2FsdA$fakehashcarol\n"
    )
    csv_file = tmp_path / "users.csv"
    csv_file.write_text(csv_content, encoding="utf-8")

    creds = parse_csv_file(
        csv_file,
        user_col="user_email",
        hash_col="password_hash",
        context_cols=["full_name"],
    )
    assert len(creds) == 2
    assert creds[0].identity == "bob@company.com"
    assert "company" in creds[0].context_terms
    assert "bob" in creds[0].context_terms


def test_auto_detect_and_parse(tmp_path: Path):
    # Test auto detection of shadow format
    shadow_file = tmp_path / "etc_shadow.txt"
    shadow_file.write_text("sysadmin:$2b$12$e8POdGlHFgqWq7GfQ1L46.kIeD5W3hF9qgJ4z7r0u6t5g8v9k3y5e:19000:0:99999:7:::\n", encoding="utf-8")

    creds = auto_detect_and_parse(shadow_file)
    assert len(creds) == 1
    assert creds[0].identity == "sysadmin"
    assert creds[0].hash_type == "bcrypt"
