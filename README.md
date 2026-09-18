# TBH Security Toolkit

Authorized cybersecurity toolkit for **your own systems, labs, CTFs, and permitted assessments**.
Defensive by default. Consolidated from 28 `TulungagungBlackHat` repositories into one
modular, tested, CLI-first Python project.

## Security model

- **Lab-local by default**: `localhost`, `127.0.0.1`, RFC1918 (`10/8`, `172.16/12`, `192.168/16`),
  `.lab/.test/.local`, `example.*`. Anything else is **blocked** unless you pass
  `--allow-external --confirm-external` (you must own the target or have written permission).
- **Legacy offensive capabilities were removed, not ported**:
  - `uchil404-ddos` (unbounded Hammer flood) → bounded `toolkit loadtest` (caps, rate limit, circuit breaker).
  - `DEFACE` (WebDAV `curl -T` defacement) → `toolkit integrity` (local baseline/check, never uploads).
  - `darkfb/fbMrD4N.py` (Facebook credential attack, Python2/mechanize) → `toolkit lab auth-audit`
    (local password-policy + lockout simulator, no real accounts, no network login).
- Active probes use **safe evidence-only payloads**, timeouts, retries with backoff, concurrency caps.
- Structured logging **never records passwords, tokens, cookies, or keys**.

## Features

| Area | Command | Origin |
|---|---|---|
| Full pipeline | `toolkit scan --target URL` | TBH-AllScan/BugBounty/Recon |
| Web hardening | `toolkit web scan`, `headers`, `ssl` | TBH-Recon/CLI |
| Passive recon | `toolkit recon [--active] [--subs]` | TBH-SubFinder |
| Ports (opt-in) | `toolkit ports --target H --ports top` | TBH-PortScanner |
| DNS | `toolkit dns --domain D` | new |
| Vuln probes (safe) | inside `scan` + `web` (xss/sqli/lfi/ssrf/redirect/ssti/idor/dirs/jsleak/cors) | TBH-XSS/SQLi/LFI/SSRF/CORS/... |
| Phishing check | `toolkit osint url --value URL` | TBH-PhishDetector |
| Password audit | `toolkit osint pass --value ...` | TBH-PassStrength |
| Load test (lab) | `toolkit loadtest --target URL --requests 100 --concurrency 5 --rate 2` | replaces uchil404-ddos |
| Integrity | `toolkit integrity baseline|check PATH` | replaces DEFACE |
| Auth lab | `toolkit lab auth-audit`, `toolkit lab serve` | replaces darkfb |
| Reports | `--format json|html|md|csv -o FILE`, `toolkit report --input X --output Y` | TBH-AllScan lineage |
| Health | `toolkit info`, `toolkit doctor`, `toolkit config show|init` | new |

## Installation (clean environment)

```bash
git clone <this-repo> && cd security-toolkit
pip install -e ".[dev]"   # or: pip install -e .
toolkit info && toolkit doctor
```

Requires Python 3.11+ and `requests` only at runtime.

## Quick start (lab only)

```bash
# 1. start the bundled vulnerable demo lab (127.0.0.1 only)
python examples/lab_server.py 8000 &
# or: docker compose up   (see examples/docker-compose.yml)

# 2. scan it
toolkit scan --target http://127.0.0.1:8000
toolkit web scan --target http://127.0.0.1:8000 --format html -o reports/lab.html
toolkit recon --target http://127.0.0.1:8000 --subs
toolkit ports --target 127.0.0.1 --ports top
toolkit loadtest --target http://127.0.0.1:8000 --requests 100 --concurrency 5 --rate 2
toolkit integrity baseline ./examples/lab-www --baseline /tmp/base.json
toolkit integrity check ./examples/lab-www --baseline /tmp/base.json
toolkit lab auth-audit --password "Str0ng!Pass-2026"
toolkit osint url --value "http://192.168.0.1@evil.tk/login"
```

External assessments only with explicit authorization:

```bash
toolkit scan --target https://owned.example.com --allow-external --confirm-external
```

## Configuration

`~/.config/toolkit/config.toml` (or `--config PATH`, see `configs/default.toml`):

```toml
[toolkit]
timeout = 8.0
concurrency = 5
rate_rps = 2.0
output_dir = "reports"
log_level = "INFO"
```

Secrets are never stored in the repo — use environment variables.

## Testing

```bash
pytest --cov=toolkit -q   # 85% total, core modules 78-100%
ruff check src tests
mypy src/toolkit/core src/toolkit/scanners src/toolkit/reporting
```

Tests use a local `http.server` mock only — no public targets.

## Architecture

```
src/toolkit/
  cli/         argparse subcommands, exit codes (0 ok / 1 usage / 3 safety / 10 fail-on)
  core/        models, safety allowlist, TOML config, logging, HTTP session
  scanners/    web.py (headers/TLS/cookies/CORS/disclosure) + vuln.py (9 safe probes)
  recon/       passive DNS/HTTP/subs, opt-in active well-known checks
  network/     diagnostics + rate-limited ports + bounded loadtest
  analyzer/    file integrity baseline/check
  lab/         auth simulator + 127.0.0.1 demo app
  osint/       phishing heuristics (defensive)
  reporting/   JSON/CSV/HTML/Markdown + executive summary
  utils/       base64/url/hash helpers
```

## Responsible use

Use only on systems you own or are explicitly authorized to test (lab, CTF, contracted pentest,
bug-bounty scope). The authors accept no liability for misuse. See `SECURITY.md`.
