# TBH-Toolkit

<p align="center">
  <img src="https://img.shields.io/badge/install-1--line-2ea44f.svg" alt="Install">
  <img src="https://img.shields.io/badge/tools-20-orange.svg" alt="Tools">
  <img src="https://img.shields.io/badge/license-MIT-red.svg" alt="License">
  <img src="https://img.shields.io/badge/platform-Termux%20%7C%20Linux%20%7C%20Kali-000000.svg" alt="Platform">
</p>

One command installs the entire [Tulungagung Black Hat](https://github.com/TulungagungBlackHat) security toolset — 20 standalone Python tools for bug bounty recon, web vulnerability detection, and defensive checks.

## Install

```bash
curl -sSL https://raw.githubusercontent.com/TulungagungBlackHat/TBH-Toolkit/main/install.sh | bash
```

Or clone first, review, then run:

```bash
git clone https://github.com/TulungagungBlackHat/TBH-Toolkit
cd TBH-Toolkit
bash install.sh
```

Requirements: `git`, `python3`, `pip`. Works on Termux, Kali, and any Linux distribution.

## What Gets Installed

| Category | Tools |
|----------|-------|
| Recon | TBH-Recon, TBH-SubFinder, TBH-DirFinder, TBH-ParamFinder, TBH-JSLeak |
| Web detectors | TBH-XSS, TBH-SQLi, TBH-LFI, TBH-SSRF, TBH-SSTI, TBH-OpenRedirect, TBH-IDOR, TBH-CORS |
| Network / defensive | TBH-PortScanner, TBH-PhishDetector, TBH-PassStrength, TBH-Utils |
| Workflow | TBH-AllScan, TBH-BugBounty, TBH-CLI |

Each tool is a standalone directory with its own README — clone everything, use what you need, delete the rest.

## After Install

```bash
python3 TBH-Recon/main.py -u https://example.com --help
python3 TBH-AllScan/allscan.py --help
```

## Manage the toolset

The bundled `tbh` manager keeps every tool current after install:

```bash
python3 TBH-Toolkit/tbh list          # status: last commit, v3 flag, behind remote
python3 TBH-Toolkit/tbh update        # paced git pull across all installed tools
python3 TBH-Toolkit/tbh run TBH-XSS --help   # launch any tool with its real entry point
python3 TBH-Toolkit/tbh doctor        # python/requests/git + install health
python3 TBH-Toolkit/tbh install ALL   # clone anything missing
```

`list --json` gives machine-readable status for scripts. Exit codes: `0` ok, `1` problems found, `2` usage error.

## What This Script Does (and Doesn't)

- **Does:** `git clone --depth 1` of the 20 public TBH repositories. Skips repos that already exist. Reports failures without aborting.
- **Does not:** modify your system, run downloaded code, open ports, or touch anything outside the current directory. Read [install.sh](install.sh) — it's under 50 lines.

## Authorized Use Only

These tools are for education and for testing systems you own or are explicitly authorized to test. Each repository carries its own [SECURITY.md](https://github.com/TulungagungBlackHat/TBH-Recon/blob/main/SECURITY.md).

## License

[MIT](LICENSE) — Tulungagung Black Hat, East Java, Indonesia. Always Smile :)
