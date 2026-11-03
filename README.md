# Crackerjack 3.3

> **Continuous Identity Security, Active Cyber Deception & Compliance Platform**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![PyPI](https://img.shields.io/pypi/v/crackerjack-audit.svg)](https://pypi.org/project/crackerjack-audit/)
[![Cloudflare Pages](https://img.shields.io/badge/Live%20Platform-crackerjack--security.pages.dev-F38020?logo=cloudflare)](https://crackerjack-security.pages.dev)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Crackerjack%20Action-blue?logo=github)](https://github.com/marketplace/actions/crackerjack-security-secret-auditor)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

```
   ______                __              _            __
  / ____/________ ______/ /_____  _____ (_)___ ______/ /__
 / /   / ___/ __ `/ ___/ //_/ _ \/ ___// / __ `/ ___/ //_/
/ /___/ /  / /_/ / /__/ ,< /  __/ /   / / /_/ / /__/ ,<
\____/_/   \__,_/\___/_/|_|\___/_/ __/ /\__,_/\___/_/|_|
                                  /___/      [v3.3.0]
```

**Crackerjack 3.3** is a unified **Continuous Identity Security, Active Deception & Credential Compliance Platform** engineered for security engineers, CISOs, penetration testers, and DevSecOps teams. It pairs high-performance **multi-core multiprocessing** with defense-in-depth standards (**NIST SP 800-63B**, **PCI-DSS v4.0**), active cyber deception (**honeywords and canary tripwires**), **historical compliance drift tracking**, automated **SIEM & ChatOps webhooks**, and **cryptographic posture hygiene auditing**.

---

## ⚠️ Responsible Use & Security Disclaimer

**Crackerjack is designed and maintained exclusively for authorized security auditing, defensive credential hygiene, academic research, and policy compliance verification against NIST SP 800-63B guidelines.**

- **Authorized Testing Only**: Only audit systems, password hashes, and environments that you own or have explicit, documented authorization to assess.
- **Privacy First**: The HaveIBeenPwned breach verification utilizes k-anonymity (transmitting only a 5-character SHA-1 prefix over TLS); full plaintext passwords are never transmitted. When checking sensitive secrets locally, prefer passing values via standard input (`--stdin`) to prevent storage in shell histories.
- **Liability Disclaimer**: The authors and contributors assume no liability and are not responsible for any misuse, damage, or unauthorized activities resulting from this software. See the [GNU General Public License v3.0](LICENSE) for full warranty disclaimers.

---

## Key Features

- 🍯 **Active Cyber Deception (Honeywords & Canary Tripwires)**:
  - Generate $k-1$ decoy passwords matching a real password's exact length, character pool, and entropy characteristics (`crackerjack honey generate`).
  - Inject canary honey-hashes into Linux `/etc/shadow`, Windows Active Directory NTDS.dit, or SQL user tables (`crackerjack honey inject`).
  - Real-time tripwire detection: if an intruder cracks or submits a decoy honeyword, trigger an instant high-priority SIEM alarm (`crackerjack honey verify`).
- 📈 **Continuous Compliance Drift Ledger**:
  - SQLite-backed audit ledger (`crackerjack drift` / `crackerjack history`) recording historical audit snapshots, average entropy, and compliance score progression.
  - Generates SVG trendlines showing fleet security improvement and MTTR over time in executive HTML compliance reports.
- 📣 **SIEM & ChatOps Webhook Engine**:
  - Out-of-the-box webhook dispatch for **Slack Block Kit**, **Microsoft Teams MessageCards**, and **Generic JSON SIEMs** with HMAC-SHA256 signature verification (`--webhook <URL> --webhook-format [slack|teams|generic]`).
- 🧬 **Probabilistic & Context-Aware Mutation Engine**:
  - Generates realistic candidate password variations modeled on real-world human password construction habits (`crackerjack mutate` / `crackerjack audit --smart-mutations`).
  - Blends company tokens, quarters, calendar years, seasons, and contextual leetspeak.
- 🔬 **Cryptographic Hygiene & KDF Modernization Assessment**:
  - Audit password storage algorithms against modern OWASP and NIST guidelines (`crackerjack hygiene <FILE>`).
  - Detects deprecated algorithms (MD5, SHA-1, LM, NTLM) and low work factors (Bcrypt rounds $< 12$, PBKDF2 iterations $< 600,000$).
  - Calculates estimated GPU attack cracking speeds (8x RTX 4090 cluster) and Post-Quantum Cryptography (PQC) readiness.
  - Automatically outputs a step-by-step migration blueprint to memory-hard **Argon2id**.
- ⚡ **Multi-Core Multi-Algorithm Multiprocessing Engine**: CPU-bound memory-hard password hashing is distributed across all available CPU cores, achieving 4x–8x throughput speedups. Supports **Argon2id**, **PBKDF2-HMAC-SHA256**, and **Bcrypt**.
- 📊 **Executive HTML Compliance Reports**: Generates standalone single-file audit reports (`--report audit.html`) featuring SVG donut/bar charts, historical drift trendlines, PCI-DSS v4.0 & NIST compliance cards, cryptographic hygiene tables, and print-ready CSS for 1-click executive PDF export.
- 🚀 **Zero-RAM Compressed Wordlist Streaming**: Stream candidate passwords lazily with an $O(1)$ memory footprint across plain `.txt`, `.gz` (e.g. `rockyou.txt.gz`), `.bz2`, and `.xz` archives.
- 🛡️ **NIST SP 800-63B Policy & Health Auditor**: Evaluate passwords against official NIST Digital Identity Guidelines with contextual dictionary blocking (§5.1.1.2) and HaveIBeenPwned k-anonymity breach checking.
- 🔑 **NIST Multi-Word Passphrase Generator**: Generate cryptographically secure, memorable passphrases with certified entropy calculation (`crackerjack generate`).
- 🌐 **Zero-Dependency REST API Microservice**: Run high-performance local validation and scoring with `crackerjack serve` and interactive Swagger UI at `/docs`.
- 🔍 **DevSecOps Repository & Secret Scanner**: Pre-commit hook and directory scanner to detect leaked API tokens, private keys, and passwords before deployment (`crackerjack scan`).

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

---

## CLI Usage Guide

### 1. Active Cyber Deception & Canary Tripwires (`honey`)
Generate decoy honeywords, inject canary entries into credential stores, and monitor for unauthorized database dumps:

```bash
# 1. Generate 5 honeywords matching a real password's entropy and length
crackerjack honey generate --password "P@ssw0rd2026!" --count 5 --output tripwire.json

# 2. Inject a canary record into Linux /etc/shadow or Windows Active Directory
crackerjack honey inject --type shadow --identity canary_backup
crackerjack honey inject --type ntds --identity canary_admin --hash 31d6cfe0d16ae931b73c59d7e0c089c0

# 3. Verify an authentication attempt (triggers critical alarm if a honeyword is used!)
crackerjack honey verify --input "P@ssw0rd2026!" --file tripwire.json
crackerjack honey verify --input "P@ssw0rd2026!" --file tripwire.json --webhook https://hooks.slack.com/...
```

---

### 2. Cryptographic Hygiene & KDF Modernization (`hygiene`)
Audit password hash algorithms, work factors, and GPU cracking vulnerabilities across dumps:

```bash
# Assess cryptographic hygiene of an /etc/shadow or hash list
crackerjack hygiene /etc/shadow
crackerjack hygiene ntds_hashes.txt --format ntds
```

---

### 3. Continuous Compliance Drift & Audit Ledger (`drift` / `history`)
Track institutional compliance improvement, MTTR, and health score drift over time:

```bash
# View historical compliance drift table
crackerjack drift

# Limit to the last 5 audit runs
crackerjack drift --limit 5
```

---

### 4. Multi-Core Hash Auditing with Webhooks & Smart Mutations (`audit`)
Audit lists of hashes, `/etc/shadow` files, or Active Directory NTDS extracts:

```bash
# Standard hash audit with 8 CPU workers and SQLite ledger tracking
crackerjack audit hashes.txt --wordlist rockyou.txt.gz --workers 8 --track-history

# Executive HTML compliance report with historical trendline and Slack webhook alert
crackerjack audit hashes.txt --wordlist rockyou.txt.gz \
  --report executive-audit.html \
  --track-history \
  --smart-mutations \
  --webhook https://hooks.slack.com/services/... \
  --webhook-format slack

# Audit Linux /etc/shadow file with automatic per-account context extraction
crackerjack audit /etc/shadow --format shadow --wordlist rockyou.txt.gz --report shadow-audit.html
```

---

### 5. Probabilistic Context-Aware Password Mutator (`mutate`)
Generate high-probability candidate passwords modeled on human cognitive habits:

```bash
# Generate 50 candidates combining company name, season, and current year
crackerjack mutate --words "Acme,Finance" --context "london,admin" --count 50

# Save candidates to custom dictionary
crackerjack mutate --words "MegaCorp" --count 500 --output megacorp_candidates.txt
```

---

### 6. DevSecOps Repository Secret Scanner (`scan`)
Scan repositories, `.env` files, and configuration files for exposed secrets with SIEM alerting:

```bash
# Scan current repository
crackerjack scan .

# Enforce strict CI/CD gate with Slack webhook alerting on findings
crackerjack scan . --fail-under 75 --fail-on-breached --webhook https://hooks.slack.com/... --webhook-format slack
```

#### Pre-Commit Hook Integration
Add Crackerjack to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/superrcoop/crackerjack
    rev: v3.3.0
    hooks:
      - id: crackerjack-scan
```

---

### 7. NIST Multi-Word Passphrase Generator (`generate`)
Generate memorable, cryptographically strong multi-word passphrases with certified entropy:

```bash
# 5 words separated by hyphens, capitalized, with number and breach pre-check
crackerjack generate --words 5 --separator "-" --capitalize --number --breach-check
```

---

### 8. REST API Microservice (`serve`)
Launch a local, zero-dependency REST API for real-time validation and IAM integration:

```bash
crackerjack serve --host 0.0.0.0 --port 8000
```
Interactive Swagger UI documentation is available at `http://localhost:8000/docs`.

---

## Architecture

```
crackerjack/
├── .pre-commit-hooks.yaml      # Git pre-commit hook definition
├── pyproject.toml              # Modern build configuration (v3.3.0)
├── requirements.txt            # Core dependencies
├── src/
│   └── crackerjack/
│       ├── __init__.py         # Package version (v3.3.0)
│       ├── __main__.py         # python -m crackerjack entry point
│       ├── cli.py              # CLI commands (audit, check, honey, hygiene, drift, mutate, scan, serve)
│       ├── honey.py            # Active cyber deception (Honeywords & Canary Tripwires)
│       ├── hygiene.py          # Cryptographic posture & KDF migration analyzer
│       ├── ledger.py           # SQLite compliance ledger & historical drift tracker
│       ├── mutator.py          # Probabilistic & context-aware mutation engine
│       ├── webhooks.py         # SIEM, Slack, and MS Teams webhook dispatcher
│       ├── auditor.py          # NIST SP 800-63B policy grader & context-specific checks
│       ├── generator.py        # NIST multi-word passphrase generator (CSPRNG)
│       ├── reporter.py         # Executive HTML compliance reporter with SVG charts & drift graph
│       ├── server.py           # Zero-dependency REST API microservice (ThreadingHTTPServer)
│       ├── scanner.py          # DevSecOps repository & config secret scanner
│       ├── parsers.py          # Structured credential dump parsers (shadow, NTDS, CSV)
│       ├── breach.py           # HaveIBeenPwned k-anonymity client
│       ├── engine.py           # Multi-core multiprocessing engine (Argon2, PBKDF2, Bcrypt)
│       ├── wordlist.py         # Zero-RAM streaming loader (.txt, .gz, .bz2, .xz)
│       ├── rules.py            # Password mutation rules & generators
│       ├── ui.py               # Rich terminal visualizations, tables & panels
│       └── models.py           # Strongly-typed dataclasses
├── tests/                      # Automated test suite (76 tests passing)
│   ├── test_honey.py
│   ├── test_hygiene.py
│   ├── test_ledger.py
│   ├── test_mutator.py
│   ├── test_webhooks.py
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

## 🤖 GitHub Action CI/CD Integration

Crackerjack is available on the **GitHub Marketplace** for automated pull request auditing:

```yaml
# .github/workflows/security.yml
name: Crackerjack Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Crackerjack Secret & Policy Scanner
        uses: superrcoop/crackerjack@v3
        with:
          path: '.'
          fail-on-findings: 'true'
          min-score: '65'
```

---

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
