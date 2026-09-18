# Changelog

## 1.0.0 (2026-09-18)

- Consolidated 28 TulungagungBlackHat repos into one authorized toolkit.
- New: professional `toolkit` CLI (14 commands), safety allowlist, TOML config,
  structured logging, HTML/JSON/CSV/Markdown reporting, 85% test coverage, CI.
- Transformed (not ported): `uchil404-ddos` → bounded loadtest; `DEFACE` → integrity
  analyzer; `darkfb` → local auth lab.
- Kept and hardened: TBH-Recon/BugBounty/AllScan/CLI header+SSL logic, all 9 TBH
  single-purpose detectors as safe evidence-only probes, SubFinder (passive),
  DirFinder, JSLeak, PortScanner (rate-limited), PhishDetector, PassStrength, Utils.
