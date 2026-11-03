"""Tests for DevSecOps repository secret scanner."""

from pathlib import Path

from crackerjack.scanner import scan_directory, scan_file


def test_scan_file_detects_secrets(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_content = (
        "# Configuration\n"
        "APP_ENV=production\n"
        "DB_PASSWORD=\"supersecretpass123!\"\n"
        "DATABASE_URL=postgres://user:dbpass999@localhost:5432/mydb\n"
        "API_SECRET='my_hardcoded_token_value'\n"
    )
    env_file.write_text(env_content, encoding="utf-8")

    findings = scan_file(env_file, check_breach=False)
    assert len(findings) >= 2
    var_names = [f.variable_name.upper() for f in findings]
    assert any("PASSWORD" in v for v in var_names)
    assert any("SECRET" in v for v in var_names)

    # Verify masking
    for f in findings:
        assert "*" in f.secret_masked


def test_scan_directory_exclusions(tmp_path: Path):
    # Valid file
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    settings_file = app_dir / "settings.py"
    settings_file.write_text('ADMIN_PASSWORD = "testpassword123"\n', encoding="utf-8")

    # Excluded virtualenv directory
    venv_dir = tmp_path / ".venv" / "lib"
    venv_dir.mkdir(parents=True)
    venv_file = venv_dir / "module.py"
    venv_file.write_text('DUMMY_PASSWORD = "fakepassword123"\n', encoding="utf-8")

    findings = scan_directory(tmp_path, check_breach=False)
    # Should find the app settings password, but not the .venv file
    paths = [f.file_path for f in findings]
    assert any("settings.py" in p for p in paths)
    assert not any(".venv" in p for p in paths)
