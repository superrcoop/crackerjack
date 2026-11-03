# Crackerjack 3.2

> **Enterprise Password Health Auditor, NIST SP 800-63B Compliance Engine & DevSecOps Platform**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![PyPI](https://img.shields.io/pypi/v/crackerjack-audit.svg)](https://pypi.org/project/crackerjack-audit/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

```
   ______                __              _            __
  / ____/________ ______/ /_____  _____ (_)___ ______/ /__
 / /   / ___/ __ `/ ___/ //_/ _ \/ ___// / __ `/ ___/ //_/
/ /___/ /  / /_/ / /__/ ,< /  __/ /   / / /_/ / /__/ ,<
\____/_/   \__,_/\___/_/|_|\___/_/ __/ /\__,_/\___/_/|_|
                                  /___/      [v3.2.0]
```

**Crackerjack 3.2** is an enterprise-grade **Password Health Governance, Compliance & DevSecOps Platform** designed for security teams, sysadmins, consultants, and developers. Built from the ground up for modern Python 3.11+, it pairs high-performance **multi-core multiprocessing** with defense-in-depth standards (**NIST SP 800-63B**, **PCI-DSS v4.0**), multi-algorithm KDF support (**Argon2id**, **PBKDF2-HMAC-SHA256**, **Bcrypt**), zero-RAM compressed wordlist streaming, executive HTML reporting, a zero-dependency REST API microservice, and repository secret scanning.

---

## ⚠️ Responsible Use & Security Disclaimer

**Crackerjack is designed and maintained exclusively for authorized security auditing, defensive credential hygiene, academic research, and policy compliance verification against NIST SP 800-63B guidelines.**

- **Authorized Testing Only**: Only audit systems, password hashes, and environments that you own or have explicit, documented authorization to assess.
- **Privacy First**: The HaveIBeenPwned breach verification utilizes k-anonymity (transmitting only a 5-character SHA-1 prefix over TLS); full plaintext passwords are never transmitted. When checking sensitive secrets locally, prefer passing values via standard input (`--stdin`) to prevent storage in shell histories.
- **Liability Disclaimer**: The authors and contributors assume no liability and are not responsible for any misuse, damage, or unauthorized activities resulting from this software. See the [GNU General Public License v3.0](LICENSE) for full warranty disclaimers.

---

## Key Features

- ⚡ **Multi-Core Multi-Algorithm Multiprocessing Engine**: CPU-bound memory-hard password hashing is distributed across all available CPU cores (e.g. Apple Silicon M-series performance and efficiency cores), achieving up to 4x–8x throughput speedups. Auto-detects and audits:
  - **Argon2** (`$argon2id$`, `$argon2i$`, `$argon2d$`)
  - **PBKDF2-HMAC-SHA256** (`$pbkdf2-sha256$`, `pbkdf2_sha256$`)
  - **Bcrypt** (`$2a$`, `$2b$`, `$2y$`)
- 📊 **Executive HTML Compliance Reports**: Generates standalone single-file audit reports (`--report audit.html`) featuring SVG charts, fleet health scoring, PCI-DSS v4.0 & NIST compliance cards, findings tables, and print-ready CSS for 1-click executive PDF generation.
- 🚀 **Zero-RAM Compressed Wordlist Streaming**: Stream candidate passwords lazily with an $O(1)$ memory footprint. Native, transparent decompression for:
  - Plain text (`.txt`, `.dic`, `.words`)
  - Gzip (`.gz`, e.g. `rockyou.txt.gz`)
  - Bzip2 (`.bz2`)
  - Xz/LZMA (`.xz`, `.lzma`)
- 🛡️ **NIST SP 800-63B Policy & Health Auditor**: Evaluate passwords against official NIST Digital Identity Guidelines:
  - Enforces minimum length requirements ($\ge 8$ characters, recommended $\ge 15$).
  - **Context-Specific Dictionary Checks (§5.1.1.2)**: Compares passwords against user details, company names, or service handles (`--context "acme,admin,john.doe"`).
  - Evaluates raw and effective Shannon information entropy.
  - Detects keyboard walks (`qwerty`, `12345`), repetition (`aaaa`), and common dictionary roots (including leetspeak).
  - Computes objective letter grades (**A+**, **A**, **B**, **C**, **D**, **F**) with actionable remediation tips.
- 🔑 **NIST Multi-Word Passphrase Generator**: Generate cryptographically secure, memorable passphrases using CSPRNG selection (`secrets.choice`) with certified entropy calculation and optional breach pre-checking (`crackerjack generate`).
- 🌐 **Zero-Dependency REST API Microservice**: Start a high-performance local validation and scoring server with `crackerjack serve`. Features `/v1/validate`, `/v1/evaluate`, `/v1/generate`, `/openapi.json`, and interactive Swagger UI docs.
- 🔍 **DevSecOps Repository & Config Scanner**: Scan codebases, `.env` files, and YAML/JSON configurations for hardcoded secrets and enforce CI/CD quality gates (`crackerjack scan`).
- 📁 **Structured Credential Dump Ingestion**: Automatic parsing and context extraction from Linux `/etc/shadow`, Windows Active Directory NTDS.dit (`username:RID:LM:NTLM`), and CSV user lists.
- 🎨 **Modern Rich Terminal UI**: Colored terminal interface with styled tables, health badges, progress bars, live hash rates ($H/s$), and elapsed timers powered by `typer` and `rich`.

---

## Installation

### From PyPI
```bash
pip install crackerjack-audit
```

### From Source
```bash
git clone https://github.com/superrcoop/crackerjack.git
cd crackerjack
pip install -e .
```

Both `crackerjack` and `crackerjack-audit` commands are registered as CLI entrypoints.

---

## CLI Usage

### 1. Audit Plaintext Password Health (`check`)
Perform a NIST SP 800-63B health audit and HaveIBeenPwned breach check on a candidate password:

```bash
# Interactive check (prompts securely without echoing)
crackerjack check

# Check with context-specific dictionary terms (NIST SP 800-63B §5.1.1.2)
crackerjack check "AcmeCorp2026!" --context "acme,admin,johndoe"

# Check with masked display
crackerjack check "Correct-Horse-Battery-Staple-2026!"

# Offline mode (skips HaveIBeenPwned network check)
crackerjack check "MySecretPassword123" --no-hibp

# Output structured JSON (useful for CI/CD pipelines)
crackerjack check "Admin2024!" --json
```

---

### 2. Multi-Core Hash & Credential Auditing (`audit`)
Audit lists of hashes, `/etc/shadow` dumps, or Active Directory NTDS extracts with streaming wordlists and generate executive HTML compliance reports:

```bash
# Standard hash audit with 8 CPU workers
crackerjack audit hashes.txt --wordlist rockyou.txt.gz --workers 8

# Generate an Executive HTML Compliance Report
crackerjack audit hashes.txt --wordlist rockyou.txt.gz --report executive-audit.html

# Audit Linux /etc/shadow file with automatic per-account context extraction
crackerjack audit /etc/shadow --format shadow --wordlist rockyou.txt.gz --report shadow-audit.html

# Audit CSV user export
crackerjack audit users.csv --format csv --wordlist rockyou.txt.gz
```

---

### 3. Generate NIST-Compliant Passphrases (`generate`)
Generate memorable, cryptographically strong multi-word passphrases with certified entropy:

```bash
# Default 4-word passphrase with number and breach pre-check
crackerjack generate

# 5 words separated by underscores, capitalized, with custom symbol
crackerjack generate --words 5 --separator "_" --capitalize --symbol

# JSON output for automated provisioning scripts
crackerjack generate --words 4 --json
```

---

### 4. REST API Microservice (`serve`)
Launch a local, zero-dependency REST API for real-time signup validation and IAM webhook integration:

```bash
# Start API server on port 8000
crackerjack serve --host 0.0.0.0 --port 8000
```

*Endpoints:*
- `GET /docs`: Interactive Swagger UI documentation
- `GET /v1/health`: System health status
- `POST /v1/validate`: Fast boolean validation for user registration/password reset forms
- `POST /v1/evaluate`: Detailed NIST SP 800-63B audit and entropy analysis
- `POST /v1/generate`: Passphrase generation with certified entropy
- `GET /openapi.json`: OpenAPI 3.0 schema

---

### 5. DevSecOps Repository Secret Scanner (`scan`)
Scan repositories, `.env` files, and configuration files for exposed or weak credentials before deployment:

```bash
# Scan current repository
crackerjack scan .

# Enforce strict CI/CD gate (fail if score < 75 or if any credential is in a breach)
crackerjack scan . --fail-under 75 --fail-on-breached

# Output findings in JSON
crackerjack scan . --json
```

#### Pre-Commit Hook Integration
Add Crackerjack to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/superrcoop/crackerjack
    rev: v3.2.0
    hooks:
      - id: crackerjack-scan
```

---

### 6. Generate Secure Hashes (`hash`)
Generate cryptographically strong hashes with custom algorithms and cost factors:

```bash
# Bcrypt (default, cost rounds 4-31)
crackerjack hash "mySuperSecretPassphrase" --algo bcrypt --cost 12

# Argon2id (modern memory-hard KDF)
crackerjack hash "mySuperSecretPassphrase" --algo argon2id --cost 2

# PBKDF2-HMAC-SHA256 (NIST approved key stretching)
crackerjack hash "mySuperSecretPassphrase" --algo pbkdf2-sha256 --cost 100000
```

---

### 7. Benchmark Multi-Core CPU Performance (`benchmark`)
Compare single-core baseline vs multi-core throughput on your machine across algorithms:

```bash
crackerjack benchmark --algo bcrypt --cost 10 --rounds 16
crackerjack benchmark --algo argon2id --cost 2 --rounds 8
crackerjack benchmark --algo pbkdf2-sha256 --cost 50000 --rounds 16
```

---

### 8. Check Environment & Version (`version`)
```bash
crackerjack version
```

---

## Architecture

```
crackerjack/
├── .pre-commit-hooks.yaml      # Git pre-commit hook definition
├── pyproject.toml              # Modern PEP 517 build configuration
├── requirements.txt            # Pinned dependencies
├── src/
│   └── crackerjack/
│       ├── __init__.py         # Package version (v3.2.0)
│       ├── __main__.py         # python -m crackerjack entry point
│       ├── cli.py              # Typer command definitions (check, audit, generate, serve, scan)
│       ├── auditor.py          # NIST SP 800-63B policy grader, context checks & entropy
│       ├── generator.py        # NIST multi-word passphrase generator (CSPRNG)
│       ├── reporter.py         # Executive HTML compliance reporter with SVG charts
│       ├── server.py           # Zero-dependency REST API microservice (ThreadingHTTPServer)
│       ├── scanner.py          # DevSecOps repository & config secret scanner
│       ├── parsers.py          # Structured credential dump parsers (shadow, NTDS, CSV)
│       ├── breach.py           # HaveIBeenPwned k-anonymity client
│       ├── engine.py           # Multi-core multiprocessing engine (Argon2, PBKDF2, Bcrypt)
│       ├── wordlist.py         # Zero-RAM streaming loader (.txt, .gz, .bz2, .xz)
│       ├── rules.py            # Password mutation rules & generators
│       ├── ui.py               # Rich terminal visual components, tables & panels
│       └── models.py           # Strongly-typed dataclasses
├── tests/                      # Automated test suite
│   ├── test_auditor.py
│   ├── test_breach.py
│   ├── test_cli.py
│   ├── test_engine.py
│   ├── test_generator.py
│   ├── test_parsers.py
│   ├── test_reporter.py
│   ├── test_rules.py
│   ├── test_scanner.py
│   ├── test_server.py
│   └── test_wordlist.py
└── data/                       # Wordlists & sample dictionaries
```

---

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
