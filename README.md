# TBH Toolkit

Security testing toolkit for **authorized targets only**. Started out as a pile
of separate repos (TBH-XSS, TBH-Recon, ...), got tired of cloning 20 repos on
my phone, so everything moved here behind one `tbh` command with a menu.

MIT license, no warranty. Don't be stupid with it.

## Install

```bash
git clone --depth 1 https://github.com/TulungagungBlackHat/TBH-Toolkit
python3 -m pip install --user requests
python3 TBH-Toolkit/tbh        # menu
```

Or `curl -fsSL https://raw.githubusercontent.com/TulungagungBlackHat/TBH-Toolkit/main/install.sh | bash`

Needs python 3.8+ and `requests`. Works on Termux, linux, mac.

## Usage

Run `tbh` with no args on a terminal, you get a numbered menu. Pick a tool,
paste URL, add extra flags if you need them.

Want something prettier? `tbh ui` opens a curses interface (tools / scan /
findings / config, j-k to move, enter to run, q to quit). Works fine in Termux.

```
tbh> 1
    target URL (blank = tool's own menu/help): https://example.com
    extra flags (optional): --ssl -p
```

Direct mode for scripts / people who hate menus:

```bash
python3 tbh recon -u https://example.com --ssl -p -s
python3 tbh xss -u 'https://example.com/?q=test' --param all --json out.json
python3 tbh web -u https://example.com --json r.json --html r.html
python3 tbh cors --targets urls.txt
python3 tbh dirfinder -u https://example.com --depth 2
python3 tbh utils hash -t secret123
```

`python3 tbh <tool> --help` shows the flags. Most tools also take
`--json`, `--proxy`, `--cookie`, `-H`, `--timeout`, `--no-color`.
Exit codes: `0` nothing found, `1` found something, `2` error.

## scan, config, findings

the stuff that makes 17 tools feel like one toolkit:

```bash
python3 tbh scan -u https://example.com            # recon + cheap detectors
python3 tbh scan -u https://example.com --deep     # + subs, dirs, js, ports, phish
python3 tbh scan -u https://example.com --html report.html

python3 tbh config set proxy http://127.0.0.1:8080  # saved in ~/.tbh/config.json
python3 tbh config set cookie "session=abc"         # every tool picks these up
python3 tbh config                                  # show what's saved

python3 tbh findings                                # what scan has saved
python3 tbh ui                                      # curses UI for all of it
```

config only adds flags you didn't already pass, and only to tools that
actually support them (portscan won't choke on --proxy, etc).

## What's inside

| command | does | was |
|---|---|---|
| recon | headers + ssl + ports + subdomains, one pass | TBH-Recon |
| subfinder | subdomains, checks cname takeover | TBH-SubFinder |
| dirfinder | dir brute, catches .git/.env leaks, has --depth | TBH-DirFinder |
| paramfinder | hidden params, active + from js/wordlist | TBH-ParamFinder |
| jsleak | grep secrets out of js files | TBH-JSLeak |
| xss | reflected xss, blind mode w/ callback url | TBH-XSS |
| sqli | error-based sqli | TBH-SQLi |
| lfi | path traversal | TBH-LFI |
| ssrf | url param ssrf, --collab for oob | TBH-SSRF |
| ssti | jinja/ruby/etc, dual-math trick | TBH-SSTI |
| redirect | open redirect | TBH-OpenRedirect |
| idor | id swap probe | TBH-IDOR |
| cors | cors misconfig | TBH-CORS |
| portscan | top-100 ports + banners | TBH-PortScanner |
| phish | phishing url heuristics | TBH-PhishDetector |
| passstrength | password score + generator | TBH-PassStrength |
| utils | base64/url/hash/jwt/qr | TBH-Utils |
| web | 34-check suite + html report | TBH-CLI |

Old per-tool repos are archived, code lives here now (same flags as before).
`tbh list` prints the module versions.

## Other stuff

- `tbh doctor` — checks python + requests are ok
- `tbh update` — just git pull

## Known stuff / notes

- portscan is single-threaded on purpose — when I parallelized it I kept
  getting junk banners on shared hosts, left it slow and correct
- `web` is the old TBH-CLI, its interactive menu still works via `tbh web`
- no built-in rate limit, be nice to targets
- tested mostly on Termux (oneplus, android 14) but linux/mac should be fine
- if a tool randomly dies with SSL errors, it's usually the target's cert,
  use `--no-color` and check manually

PRs welcome. Keep new flags consistent with the other tools please.
