#!/usr/bin/env python3
"""TBH-JSLeak v3 - Secret scanner for JavaScript assets (authorized testing only).

Scans the target page plus its linked JS files. Secrets are masked in output;
full values only go into the JSON report when --full is given.
"""
import argparse, json, os, re, sys, time, urllib.parse

try:
    import requests
except ImportError:
    print("[!] requests required: pip install requests", file=sys.stderr)
    sys.exit(2)

VERSION = "3.0"
REPO = "https://github.com/TulungagungBlackHat/TBH-JSLeak"

def banner():
    if os.environ.get("NO_COLOR"):
        return ""
    return ("\033[91m╔════════════════════════════════════╗\n"
            "║ \033[97mTBH-JSLeak v3\033[91m - JS Secret Scan    ║\n"
            "║ \033[90mTulungagung Black Hat | uchil404 \033[91m║\n"
            "╚════════════════════════════════════╝\033[0m")

def color(code, text, enabled=True):
    return f"\033[{code}m{text}\033[0m" if enabled else text

PATTERNS = {
    "aws-access-key": r"\b(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b",
    "google-api-key": r"\bAIza[0-9A-Za-z_\-]{35}\b",
    "slack-webhook": r"https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+",
    "stripe-live-key": r"\bsk_live_[0-9a-zA-Z]{24,}\b",
    "private-key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "jwt": r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b",
    "github-token": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
    "generic-api-key": r"""(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*["']([A-Za-z0-9_\-]{16,})["']""",
    "generic-password": r"""(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*["']([^"']{6,})["']""",
    "basic-auth-url": r"\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@[^/\s]+",
}
JS_LINK_RE = re.compile(r"""(?:src|href)\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']""", re.I)
INLINE_JS_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.I | re.S)

def mask(value, full):
    if full or len(value) <= 8:
        return value
    return value[:6] + "…" + f"(len={len(value)})"

def build_session(args):
    s = requests.Session()
    s.headers["User-Agent"] = f"TBH-JSLeak/{VERSION} (+{REPO})"
    if args.cookie:
        s.headers["Cookie"] = args.cookie
    for h in args.header or []:
        name, _, val = h.partition(":")
        if val:
            s.headers[name.strip()] = val.strip()
    if args.proxy:
        s.proxies = {"http": args.proxy, "https": args.proxy}
    return s

def scan_text(text, source, full):
    findings = []
    for name, pat in PATTERNS.items():
        for m in re.finditer(pat, text):
            value = m.group(1) if m.groups() else m.group(0)
            findings.append({"type": name, "source": source,
                             "value_masked": mask(value, full),
                             "value": value if full else None,
                             "excerpt": text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")})
    return findings

def resolve_js_links(page_url, links, limit):
    base = urllib.parse.urljoin(page_url, "/")
    out, seen = [], set()
    for link in links:
        absu = urllib.parse.urljoin(page_url, link)
        host = urllib.parse.urlparse(absu).netloc
        page_host = urllib.parse.urlparse(page_url).netloc
        if host and host != page_host and not args_same_site(host, page_host):
            continue
        if absu in seen:
            continue
        seen.add(absu)
        out.append(absu)
        if len(out) >= limit:
            break
    return out

def args_same_site(host, page_host):
    return host == page_host or host.endswith("." + page_host) or page_host.endswith("." + host)

def main():
    parser = argparse.ArgumentParser(description=f"TBH-JSLeak v{VERSION}")
    parser.add_argument("-u", "--url", required=True, help="page URL that loads JS")
    parser.add_argument("--max-js", type=int, default=10, help="max JS files to fetch (default 10)")
    parser.add_argument("--full", action="store_true", help="include full secret values in JSON (handle carefully)")
    parser.add_argument("--proxy", help="e.g. http://127.0.0.1:8080")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("-H", "--header", action="append", help="extra header, repeatable")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--json", help="save JSON report")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"TBH-JSLeak {VERSION}")
    args = parser.parse_args()
    print(banner())

    use_color = not args.no_color and not os.environ.get("NO_COLOR")
    print(color("91", "[!] Authorized scopes only. Report secrets - don't use them.", use_color))

    session = build_session(args)
    try:
        r = session.get(args.url, timeout=args.timeout, allow_redirects=True)
    except requests.RequestException as e:
        print(color("91", f"[!] request failed: {e}", use_color), file=sys.stderr)
        sys.exit(2)

    all_findings = scan_text(r.text, args.url, args.full)

    links = JS_LINK_RE.findall(r.text)
    js_urls = resolve_js_links(args.url, links, args.max_js)
    print(f"[*] Page {r.status_code} | JS links: {len(links)} -> fetching {len(js_urls)}")

    for js_url in js_urls:
        try:
            jr = session.get(js_url, timeout=args.timeout)
        except requests.RequestException as e:
            print(color("90", f"[-] {js_url}: {e}", use_color))
            continue
        hits = scan_text(jr.text, js_url, args.full)
        all_findings.extend(hits)
        print(f"[+] {js_url} ({len(jr.text)}b, {len(hits)} hits)")
        if args.delay:
            time.sleep(args.delay)

    for inline in INLINE_JS_RE.findall(r.text):
        all_findings.extend(scan_text(inline, args.url + "#inline", args.full))

    by_type = {}
    for f in all_findings:
        by_type.setdefault(f["type"], []).append(f)

    if all_findings:
        print(color("91", f"\n[!] {len(all_findings)} potential secret(s):", use_color))
        for f in all_findings:
            print(color("91", f"  [{f['type']}] {f['value_masked']}  <- {f['source']}", use_color))
        print(color("93", "-> Verify validity, then report. Do NOT use found credentials.", use_color))
    else:
        print(color("92", "[✓] No secret patterns matched", use_color))

    if args.json:
        report = {"tool": "TBH-JSLeak", "version": VERSION, "target": args.url,
                  "js_scanned": js_urls, "summary": {"total": len(all_findings), "by_type": {k: len(v) for k, v in by_type.items()}},
                  "findings": all_findings}
        try:
            with open(args.json, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"[✓] JSON: {args.json}")
        except OSError as e:
            print(color("91", f"[!] cannot write JSON: {e}", use_color), file=sys.stderr)
            sys.exit(2)

    sys.exit(1 if all_findings else 0)

if __name__ == "__main__":
    main()
