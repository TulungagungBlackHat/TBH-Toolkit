# TBH Toolkit

> **TBH v4 — one repo, one command.** The whole Tulungagung Black Hat security toolset
> (17 tools, 50+ modules) now lives here behind a single menu-driven CLI.

> [!IMPORTANT]
> **Authorized testing only.** Use against targets you own or have written permission to test.
> See [SECURITY.md](SECURITY.md). No warranty — see [LICENSE](LICENSE) (MIT).

[![CI](https://github.com/TulungagungBlackHat/TBH-Toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/TulungagungBlackHat/TBH-Toolkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20Linux%20%7C%20macOS-blue.svg)]()

---

## Install (5 seconds)

```bash
git clone --depth 1 https://github.com/TulungagungBlackHat/TBH-Toolkit
python3 -m pip install --user requests
python3 TBH-Toolkit/tbh
```

or with the helper:

```bash
curl -fsSL https://raw.githubusercontent.com/TulungagungBlackHat/TBH-Toolkit/main/install.sh | bash
```

## Menu

Run with no arguments on a terminal and pick a tool by number:

```
╔════════════════════════════════════╗
║   TBH Toolkit v4.0  -  Menu       ║
║   Tulungagung Black Hat           ║
╚════════════════════════════════════╝
  [ 1] recon         Web recon: headers, SSL, ports, subdomains
  [ 2] subfinder     Subdomain enum + CNAME takeover detection
  [ 3] dirfinder     Directory discovery with recursion (--depth)
  ...
  [18] web           34-module web check suite
  [ D] doctor        environment check
  [ U] update        git pull this toolkit
  [ 0] exit
──────────────────────────────────────
tbh> 1
    target URL (blank = tool's own menu/help): https://example.com
    extra flags (optional, e.g. --param all --json r.json): --ssl
```

## Direct mode (scripts, CI)

Every subcommand also works headless with full flags and stable exit codes
(`0` clean · `1` finding · `2` error):

```bash
python3 tbh recon -u https://example.com --ssl -p -s
python3 tbh xss -u 'https://example.com/?q=test' --param all --json out.json
python3 tbh web -u https://example.com --json r.json --html r.html
python3 tbh cors --targets urls.txt
python3 tbh dirfinder -u https://example.com --depth 2
python3 tbh portscan -u example.com
python3 tbh list        # tool versions
python3 tbh doctor      # environment check
python3 tbh update      # git pull
```

Per-tool flags: `python3 tbh <tool> --help`.

## Tools

| # | Subcommand | What it does | Old repo |
|---|------------|--------------|----------|
| 1 | `recon` | Web recon: headers, SSL, ports, subdomains | TBH-Recon |
| 2 | `subfinder` | Subdomain enum + CNAME takeover detection | TBH-SubFinder |
| 3 | `dirfinder` | Directory discovery, leaked `.git`/`.env` (with `--depth` recursion) | TBH-DirFinder |
| 4 | `paramfinder` | Hidden parameter discovery (active + passive) | TBH-ParamFinder |
| 5 | `jsleak` | Secrets hunting in JavaScript | TBH-JSLeak |
| 6 | `xss` | Reflected XSS (multi-payload, blind callback) | TBH-XSS |
| 7 | `sqli` | Error-based SQL injection | TBH-SQLi |
| 8 | `lfi` | Path traversal / LFI | TBH-LFI |
| 9 | `ssrf` | SSRF (URL params, OOB collab) | TBH-SSRF |
| 10 | `ssti` | Template injection (dual-math) | TBH-SSTI |
| 11 | `redirect` | Open redirect | TBH-OpenRedirect |
| 12 | `idor` | IDOR probe (ID swap window) | TBH-IDOR |
| 13 | `cors` | CORS misconfiguration | TBH-CORS |
| 14 | `portscan` | Port scan: top-100, banners, CVE hints | TBH-PortScanner |
| 15 | `phish` | Phishing URL detector (12 heuristics) | TBH-PhishDetector |
| 16 | `passstrength` | Password strength + generator | TBH-PassStrength |
| 17 | `utils` | b64/url/hash/jwt/qr utilities | TBH-Utils |
| 18 | `web` | 34-module web check suite + HTML report | TBH-CLI |

The per-tool repositories have been **archived** (banner points here); no functionality was lost — everything above is the same code, same flags, same exit codes.

## Why one repo?

- **Install in seconds** — one clone instead of seventeen
- **Update in one place** — `tbh update` = `git pull`
- **Consistent UX** — shared menu, shared flags (`--json`, `--proxy`, `--cookie`, `-H`, `--timeout`, `--version`, `--no-color`), shared exit codes
- **No duplicated maintenance** — fixes land once

## Standards

Every tool follows the TBH v3+ contract:

- `--proxy / --cookie / -H / --timeout / --json / --version / --no-color`
- Exit codes: `0` clean, `1` finding, `2` error
- JSON schema `{tool, version, target, findings, summary}` (multi-target adds `targets[]`)
- Baseline request before any payload is sent
- Authorized-use warning in `--help`

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New tools = new file in `modules/` +
one line in `REGISTRY` (inside `tbh`).

## Changelog

See [CHANGELOG.md](CHANGELOG.md). v4.0.0 is the monorepo merge; the tools keep
their own module versions (e.g. `xss v3.1`) shown in `tbh list`.

---

<p align="center"><b>Tulungagung Black Hat</b><br>
Authorized testing only. MIT licensed. Not affiliated with any bug bounty platform.</p>
