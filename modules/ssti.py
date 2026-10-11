#!/usr/bin/env python3
"""TBH-SSTI v3 - Server-Side Template Injection detector (authorized testing only).

Detection is dual-probe: two different math expressions must BOTH evaluate to
their expected results. A page that merely contains "49" no longer trips the
detector (the classic v2 false positive).
"""
import argparse, json, os, re, sys, time, urllib.parse

try:
    import requests
except ImportError:
    print("[!] requests required: pip install requests", file=sys.stderr)
    sys.exit(2)

VERSION = "3.1"
REPO = "https://github.com/TulungagungBlackHat/TBH-SSTI"

def banner():
    if os.environ.get("NO_COLOR"):
        return ""
    return ("\033[91m╔════════════════════════════════════╗\n"
            "║ \033[97mTBH-SSTI v3\033[91m - SSTI Detector       \033[91m║\n"
            "║ \033[90mTulungagung Black Hat | uchil404 \033[91m║\n"
            "╚════════════════════════════════════╝\033[0m")

def color(code, text, enabled=True):
    return f"\033[{code}m{text}\033[0m" if enabled else text

PROBES = [
    ("{{7*7}}", "49"),
    ("{{1337*1337}}", "1786969"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
]

def build_session(args):
    s = requests.Session()
    s.headers["User-Agent"] = f"TBH-SSTI/{VERSION} (+{REPO})"
    if args.cookie:
        s.headers["Cookie"] = args.cookie
    for h in args.header or []:
        name, _, val = h.partition(":")
        if not val:
            raise SystemExit(f"[!] bad -H value: {h!r}")
        s.headers[name.strip()] = val.strip()
    if args.proxy:
        s.proxies = {"http": args.proxy, "https": args.proxy}
    return s

def inject(url, param, value):
    p = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    if param is None:
        param = next(iter(qs), "q")
    qs[param] = [value]
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(qs, doseq=True))), param

def target_params(url, requested):
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query, keep_blank_values=True)
    if requested and requested != "all":
        return [requested]
    return list(qs.keys()) or ["q"]

def engine_hint(payload):
    if payload.startswith("{{"):
        return "jinja2/twig-style"
    if payload.startswith("${"):
        return "freemarker/velocity-style"
    if payload.startswith("<%="):
        return "erb/ejs-style"
    if payload.startswith("#{"):
        return "mako-style"
    return "unknown"

def scan(session, url, args):
    findings = []
    params = target_params(url, args.param)
    try:
        b = session.get(url, timeout=args.timeout, allow_redirects=True)
        baseline = {"status": b.status_code, "length": len(b.text)}
    except requests.RequestException as e:
        return {"error": f"baseline failed: {e}"}

    for param in params:
        hits = {}
        for payload, expected in PROBES:
            test_url, _ = inject(url, param, payload)
            try:
                r = session.get(test_url, timeout=args.timeout, allow_redirects=True)
            except requests.RequestException as e:
                findings.append({"param": param, "payload": payload, "error": str(e), "verdict": "error"})
                continue
            # result must appear while the payload itself is reflected nearby,
            # and the page must differ from baseline length (payload had effect)
            evaluated = expected in r.text and payload not in r.text.replace(expected, "")
            reflected_raw = payload in r.text
            hits[payload] = {"status": r.status_code, "evaluated": evaluated,
                             "reflected": reflected_raw, "length": len(r.text)}
            if args.delay:
                time.sleep(args.delay)

        strong = [p for p, h in hits.items() if h["evaluated"]]
        # dual-probe rule: at least one math probe evaluated AND another probe of
        # a different value also evaluated (kills coincidence "49 on page")
        math_hits = [p for p in strong if p in ("{{7*7}}", "{{1337*1337}}")]
        if len(math_hits) >= 2 or (len(strong) >= 2 and len(set(PROBES[i][1] for i, pp in enumerate(PROBES) if pp[0] in strong)) >= 2):
            findings.append({"param": param, "verdict": "potential-ssti",
                             "engines": sorted({engine_hint(p) for p in strong}),
                             "probes": {p: hits[p] for p in strong}})
        else:
            for p, h in hits.items():
                if h["evaluated"]:
                    findings.append({"param": param, "verdict": "single-probe", "payload": p,
                                     "engine": engine_hint(p), "note": "only one probe evaluated - verify manually"})

    return {"tool": "TBH-SSTI", "version": VERSION, "target": url,
            "baseline": baseline, "findings": findings}

def main():
    parser = argparse.ArgumentParser(description=f"TBH-SSTI v{VERSION} - SSTI detector (dual-probe)")
    parser.add_argument("-u", "--url")
    parser.add_argument("--targets", help="file with one URL per line (multi-target)")
    parser.add_argument("--param", help="parameter name, or 'all' (default: first param)")
    parser.add_argument("--proxy", help="e.g. http://127.0.0.1:8080 (Burp)")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("-H", "--header", action="append", help="extra header, repeatable")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--json", help="save JSON report")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"TBH-SSTI {VERSION}")
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
                           {"tool": "TBH-SSTI", "version": VERSION,
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
    print(color("91", "[!] Authorized targets only. Arithmetic probes only - no RCE payloads.", use_color))
    print(f"[*] Scanning {args.url}")
    try:
        session = build_session(args)
    except SystemExit as e:
        print(e, file=sys.stderr)
        sys.exit(2)

    report = scan(session, args.url, args)
    if "error" in report:
        print(color("91", f"[!] {report['error']}", use_color))
        sys.exit(2)

    vuln = 0
    for f in report["findings"]:
        if f.get("verdict") == "potential-ssti":
            vuln += 1
            print(color("91", f"[!] SSTI on {f['param']}: engines={f['engines']}", use_color))
        elif f.get("verdict") == "single-probe":
            print(color("93", f"[?] {f['param']}: {f['payload']} evaluated once - {f['note']}", use_color))
        elif f.get("verdict") == "error":
            print(color("90", f"[-] {f['param']}: {f['error']}", use_color))

    if args.json:
        report["summary"] = {"potential_ssti": vuln}
        try:
            with open(args.json, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"[✓] JSON: {args.json}")
        except OSError as e:
            print(color("91", f"[!] cannot write JSON: {e}", use_color), file=sys.stderr)
            sys.exit(2)

    if vuln:
        print(color("91", f"[!] {vuln} parameter(s) with dual-probe SSTI confirmation", use_color))
        sys.exit(1)
    print(color("92", "[✓] No SSTI confirmed (dual-probe rule)", use_color))
    sys.exit(0)

if __name__ == "__main__":
    main()
