# Changelog

## [1.0.0] - 2026-10-10
### Added
- `tbh` manager CLI: list, update (paced git pull), install, run, doctor
- Per-tool status: last commit, v3 changelog flag, ahead/behind remote
- JSON output for list; exit codes (0 ok, 1 problems, 2 usage errors)
- CI workflow (compile + self-test + installer lint)
### Fixed
- Missing repo standards: SECURITY.md, CONTRIBUTING.md, CHANGELOG.md now present

## [4.1.0] - 2026-10-11
- `tbh ui` - curses interface (tools / scan / findings / config), termux friendly
- `tbh scan` - run many tools at once against one target, combined json/html,
  logs under ~/.tbh/logs/
- `tbh config` - save proxy/cookie/timeout/headers in ~/.tbh/config.json,
  every tool picks them up automatically (menu, cli, ui, scan)
- `tbh findings` - what scan has saved so far
- menu remembers last target, accepts tool names not just numbers

## [4.0.0] - 2026-10-11
- merged all 17 tool repos into this one. code moved as-is, same flags,
  same exit codes. module versions unchanged (see `tbh list`)
- bare `tbh` opens a numbered menu now (pick tool, paste url, extra flags)
- `tbh list` / `tbh doctor` / `tbh update` while i was at it
- install.sh only clones this repo now instead of 20
- old per-tool repos archived with a banner pointing here
