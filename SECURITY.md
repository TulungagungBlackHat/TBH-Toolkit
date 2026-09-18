# Security Policy

## Scope

This toolkit is for **authorized testing only**: your own systems, isolated labs,
CTFs, contracted penetration tests, and in-scope bug-bounty targets.

## What this project will never do

- Credential theft, phishing kits, account takeover, password cracking vs real accounts
- DDoS / unbounded flooding (the legacy Hammer script was replaced by a capped lab loadtest)
- Defacement / destructive modification (the legacy WebDAV PUT flow was replaced by integrity monitoring)
- Backdoors, persistence, malware, session/token theft

## Reporting a vulnerability (in this toolkit itself)

Open a GitHub issue with `[SECURITY]` prefix or contact the maintainers privately.
Please include: affected module, reproduction on `127.0.0.1`, expected vs actual behavior.

## Self-audit notes

- No `shell=True`, no `eval`, no `pickle`, no dynamic code execution on user input.
- No arbitrary file write: report/baseline paths are user-specified outputs only; no path traversal
  into system dirs (outputs default to `./reports`).
- SSRF contained: active fetchers only request the user-supplied lab target; SSRF probe uses
  reserved `192.0.2.1.invalid`, never cloud metadata.
- Subprocess: none used. Temporary files: none (baselines are explicit user files).
- Dependencies: `requests` only at runtime; dev tools pinned via `pip-audit` in CI.
- Secrets: CI greps for `ghp_`, `AKIA`, private keys, hardcoded passwords.
