# Crackerjack 3.1

> **Modern Multi-Core Password Health Auditor, Multi-Algorithm KDF Engine & NIST SP 800-63B Compliance Checker**

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
                                  /___/      [v3.1.0]
```

**Crackerjack 3.1** transforms Crackerjack into an enterprise-grade **Password Health & Breach Auditor** designed for security teams, sysadmins, and developers. Built from the ground up for modern Python 3.11+, it pairs high-performance **multi-core multiprocessing** with defense-in-depth security standards like **NIST SP 800-63B**, multi-algorithm KDF support (**Argon2id**, **PBKDF2-HMAC-SHA256**, **Bcrypt**), zero-RAM compressed wordlist streaming, and the **HaveIBeenPwned** k-anonymity breach API.

---

## Key Features

- ⚡ **Multi-Core Multi-Algorithm Multiprocessing Engine**: CPU-bound memory-hard password hashing is distributed across all available CPU cores (e.g. Apple Silicon M-series performance and efficiency cores), achieving up to 4x–8x throughput speedups. Auto-detects and audits:
  - **Argon2** (`$argon2id$`, `$argon2i$`, `$argon2d$`)
  - **PBKDF2-HMAC-SHA256** (`$pbkdf2-sha256$`, `pbkdf2_sha256$`)
  - **Bcrypt** (`$2a$`, `$2b$`, `$2y$`)
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
- 🌐 **HaveIBeenPwned k-Anonymity Breach Detection**: Checks passwords against billions of compromised credentials via the Pwned Passwords API. Passwords are never sent over the network; only a 5-character SHA-1 prefix is transmitted, preserving complete privacy.
- 🎨 **Modern Rich Terminal UI**: Colored terminal interface with styled tables, health badges, progress bars, live hash rates ($H/s$), and elapsed timers powered by `typer` and `rich`.
- 🔄 **Hybrid Mutation Engine**: Generator-based mutation pipeline including leetspeak replacements, date/year additions, case modifications, and word reversals.
- 📦 **Standard PEP 517/621 Packaging**: Packaged as `crackerjack-audit` with `pyproject.toml` for simple `pip` installation and CLI access.

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

*Exit Codes:* Returns `0` if compliant and unbreached; returns `1` if compromised or failing NIST baseline standards.

---

### 2. Multi-Core Hash & Credential Auditing (`audit`)
Audit lists of hashes (Bcrypt, Argon2, PBKDF2) or passwords against plain or compressed wordlists utilizing all CPU cores:

```bash
# Audit hashes using 8 worker processes and a gzip-compressed wordlist
crackerjack audit hashes.txt --wordlist rockyou.txt.gz --workers 8

# Audit a single hash (auto-detects Bcrypt, Argon2id, PBKDF2)
crackerjack audit '$argon2id$v=19$...' --wordlist data/samplewords.txt

# Disable rule mutations for faster exact-match auditing
crackerjack audit hashes.txt --wordlist rockyou.txt --no-rules

# Export audit findings to JSON
crackerjack audit hashes.txt --wordlist rockyou.txt --output results.json
```

---

### 3. Generate Secure Hashes (`hash`)
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

### 4. Benchmark Multi-Core CPU Performance (`benchmark`)
Compare single-core baseline vs multi-core throughput on your machine across algorithms:

```bash
# Benchmark Bcrypt
crackerjack benchmark --algo bcrypt --cost 10 --rounds 16

# Benchmark PBKDF2
crackerjack benchmark --algo pbkdf2-sha256 --cost 50000 --rounds 16
```

---

### 5. Check Environment & Version (`version`)
```bash
crackerjack version
```

---

## Architecture

```
crackerjack/
├── pyproject.toml              # Modern PEP 517 build configuration
├── requirements.txt            # Pinned dependencies
├── src/
│   └── crackerjack/
│       ├── __init__.py         # Package version (v3.1.0)
│       ├── __main__.py         # python -m crackerjack entry point
│       ├── cli.py              # Typer command definitions
│       ├── auditor.py          # NIST SP 800-63B policy grader, context checks & entropy
│       ├── breach.py           # HaveIBeenPwned k-anonymity client
│       ├── engine.py           # Multi-core multiprocessing engine (Argon2, PBKDF2, Bcrypt)
│       ├── wordlist.py         # Zero-RAM streaming loader (.txt, .gz, .bz2, .xz)
│       ├── rules.py            # Password mutation rules & generators
│       ├── ui.py               # Rich terminal visual components & tables
│       └── models.py           # Strongly-typed dataclasses
├── tests/                      # Pytest automated test suite
│   ├── test_auditor.py
│   ├── test_breach.py
│   ├── test_cli.py
│   ├── test_engine.py
│   ├── test_rules.py
│   └── test_wordlist.py
└── data/                       # Wordlists & sample dictionaries
```

---

## Development & Testing

Run tests with `pytest`:

```bash
pytest -v
```

Build distribution packages (`sdist` and `wheel`):

```bash
python -m build
```

---

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
