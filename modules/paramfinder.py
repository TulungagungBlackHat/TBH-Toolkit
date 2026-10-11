#!/usr/bin/env python3
"""TBH-ParamFinder v3 - Hidden parameter discovery (authorized testing only).

Combines two techniques:
1. Passive: scrape the page (HTML + JS) for parameter-looking strings
2. Active: probe a wordlist of parameter names and diff responses vs baseline
"""
import argparse, json, os, re, sys, time, urllib.parse

try:
    import requests
except ImportError:
    print("[!] requests required: pip install requests", file=sys.stderr)
    sys.exit(2)

VERSION = "3.0"
REPO = "https://github.com/TulungagungBlackHat/TBH-ParamFinder"

def banner():
    if os.environ.get("NO_COLOR"):
        return ""
    return ("\033[91m╔════════════════════════════════════╗\n"
            "║ \033[97mTBH-ParamFinder v3\033[91m - Active Probe  ║\n"
            "║ \033[90mTulungagung Black Hat | uchil404 \033[91m║\n"
            "╚════════════════════════════════════╝\033[0m")

def color(code, text, enabled=True):
    return f"\033[{code}m{text}\033[0m" if enabled else text

PARAM_WORDLIST = [
    "id", "user", "uid", "account", "profile", "order", "invoice", "doc", "file",
    "page", "q", "search", "s", "query", "keyword", "lang", "language", "locale",
    "url", "redirect", "next", "return", "dest", "callback", "continue",
    "debug", "test", "admin", "role", "access", "token", "key", "api_key",
    "view", "mode", "format", "output", "type", "action", "cmd", "exec",
    "path", "dir", "folder", "include", "template", "theme", "layout",
    "sort", "order_by", "filter", "cat", "category", "tag", "limit", "offset",
    "year", "month", "day", "from", "to", "ref", "source", "utm_source",
    "password", "pass", "pwd", "email", "name", "phone", "address",
    "json", "xml", "callback2", "jsonp", "raw", "preview", "download", "export",
]
PASSIVE_PATTERNS = [
    re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]{1,40})="),
    re.compile(r"""["']([A-Za-z_][A-Za-z0-9_]{2,40})["']\s*:\s*["']?[^"'\s,]{1,40}"""),
    re.compile(r"""\b([A-Za-z_][A-Za-z0-9_]{2,40})\s*=\s*["'][^"']{1,60}["']"""),
]

def build_session(args):
    s = requests.Session()
    s.headers["User-Agent"] = f"TBH-ParamFinder/{VERSION} (+{REPO})"
    if args.cookie:
        s.headers["Cookie"] = args.cookie
    for h in args.header or []:
        name, _, val = h.partition(":")
        if val:
            s.headers[name.strip()] = val.strip()
    if args.proxy:
        s.proxies = {"http": args.proxy, "https": args.proxy}
    return s

def passive_scan(text, limit=40):
    hits = set()
    for pat in PASSIVE_PATTERNS:
        for m in pat.findall(text):
            if m.lower() not in ("function", "return", "var", "this", "document", "window"):
                hits.add(m)
    return sorted(hits)[:limit]

def add_param(url, name, value="1"):
    p = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    qs[name] = [value]
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(qs, doseq=True)))

def active_probe(session, url, args, baseline):
    existing = set(urllib.parse.parse_qs(urllib.parse.urlparse(url).query))
    accepted = []
    for name in PARAM_WORDLIST:
        if name in existing:
            continue
        test_url = add_param(url, name)
        try:
            r = session.get(test_url, timeout=args.timeout, allow_redirects=True)
        except requests.RequestException:
            continue
        delta = abs(len(r.text) - baseline["length"])
        if r.status_code != baseline["status"] or delta > max(args.threshold, baseline["length"] // 100):
            accepted.append({"param": name, "status": r.status_code,
                             "length": len(r.text), "delta": len(r.text) - baseline["length"]})
        if args.delay:
            time.sleep(args.delay)
    return accepted

def main():
    parser = argparse.ArgumentParser(description=f"TBH-ParamFinder v{VERSION}")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("--passive-only", action="store_true", help="skip active probing")
    parser.add_argument("--threshold", type=int, default=30, help="length delta to accept a param (default 30)")
    parser.add_argument("--proxy", help="e.g. http://127.0.0.1:8080")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("-H", "--header", action="append", help="extra header, repeatable")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--json", help="save JSON report")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"TBH-ParamFinder {VERSION}")
    args = parser.parse_args()
    print(banner())

    use_color = not args.no_color and not os.environ.get("NO_COLOR")
    print(color("91", "[!] Authorized scopes only.", use_color))

    session = build_session(args)
    try:
        r = session.get(args.url, timeout=args.timeout, allow_redirects=True)
    except requests.RequestException as e:
        print(color("91", f"[!] request failed: {e}", use_color), file=sys.stderr)
        sys.exit(2)

    print(f"[*] Baseline: {r.status_code} len={len(r.text)}")
    passive = passive_scan(r.text)
    print(f"[+] Passive hints ({len(passive)}): {', '.join(passive[:15])}"
          + ("..." if len(passive) > 15 else ""))

    active = []
    if not args.passive_only:
        print(f"[*] Active probing {len(PARAM_WORDLIST)} candidate params...")
        baseline = {"status": r.status_code, "length": len(r.text)}
        active = active_probe(session, args.url, args, baseline)
        for a in active:
            print(color("93", f"[+] Accepted: {a['param']} -> {a['status']} delta={a['delta']:+d}", use_color))

    report = {"tool": "TBH-ParamFinder", "version": VERSION, "target": args.url,
              "baseline": {"status": r.status_code, "length": len(r.text)},
              "passive": passive, "active": active}
    print(f"\n[✓] Passive: {len(passive)} | Active accepted: {len(active)}")
    print("-> Feed accepted params to TBH-IDOR / TBH-XSS / TBH-SQLi with --param")

    if args.json:
        try:
            with open(args.json, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"[✓] JSON: {args.json}")
        except OSError as e:
            print(color("91", f"[!] cannot write JSON: {e}", use_color), file=sys.stderr)
            sys.exit(2)

    sys.exit(1 if active else 0)

if __name__ == "__main__":
    main()
