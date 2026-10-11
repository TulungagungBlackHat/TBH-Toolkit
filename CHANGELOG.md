# Changelog

## [1.0.0] - 2026-10-10
### Added
- `tbh` manager CLI: list, update (paced git pull), install, run, doctor
- Per-tool status: last commit, v3 changelog flag, ahead/behind remote
- JSON output for list; exit codes (0 ok, 1 problems, 2 usage errors)
- CI workflow (compile + self-test + installer lint)
### Fixed
- Missing repo standards: SECURITY.md, CONTRIBUTING.md, CHANGELOG.md now present

## [4.0.0] - 2026-10-11
### Added
- Interactive numbered **menu** when run without arguments (target + extra-flags prompts).
- Unified dispatcher `tbh <tool>` with 18 subcommands, aliases (`cli`→`web`, `scanner`→`portscan`).
- Meta commands: `tbh list`, `tbh doctor`, `tbh update`.
- All 17 former per-tool repos merged into `modules/` (same flags, same exit codes).

### Changed
- `install.sh` now clones this repo only (was: 20 separate clones).
- README rewritten for the monorepo menu-first workflow.
- CI validates the dispatcher + every subcommand `--help`.

### Deprecated
- Per-tool repositories are archived with banners pointing here.
