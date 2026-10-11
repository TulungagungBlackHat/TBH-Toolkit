#!/usr/bin/env python3
"""TBH-IDOR v3 - Insecure Direct Object Reference hunting helper (authorized testing only).

Requires an authenticated session (your own account). Compares responses for
your ID vs neighboring IDs; content-length similarity with different ID is the
classic IDOR signal — always confirm manually with a second account you own.
"""
import argparse, hashlib, json, os, re, sys, time

try:
    import requests
except ImportError:
    print("[!] requests required: pip install requests", file=sys.stderr)
    sys.exit(2)

VERSION = "3.1"
REPO = "https://github.com/TulungagungBlackHat/TBH-IDOR"

def banner():
    if os.environ.get("NO_COLOR"):
        return ""
    return ("\033[91m╔════════════════════════════════════╗\n"
            "║ \033[97mTBH-IDOR v3\033[91m - Access Control       \033[91m║\n"
            "║ \033[90mTulungagung Black Hat | uchil404 \033[91m║\n"
            "╚════════════════════════════════════╝\033[0m")

def color(code, text, enabled=True):
    return f"\033[{code}m{text}\033[0m" if enabled else text

ID_PATTERN = re.compile(r"([?&])(id|user|account|profile|uid|order|invoice|doc|file|item)=(\d+)")

def build_session(args):
    s = requests.Session()
    s.headers["User-Agent"] = f"TBH-IDOR/{VERSION} (+{REPO})"
    if args.cookie:
        s.headers["Cookie"] = args.cookie
    for h in args.header or []:
        name, _, val = h.partition(":")
        if not val:
            raise SystemExit(f"[!] bad -H value: {h!r}")
        s.headers[name.strip()] = val.strip()
    if args.proxy:
        s.proxies = {"http": args.proxy, "https": args.proxy}
    if not args.cookie and not any(k.lower() == "authorization" for k in s.headers):
        print("[i] No --cookie/-H Authorization given: IDOR testing is much weaker unauthenticated.")
    return s

def fingerprint(text):
    return {"length": len(text), "sha256": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]}

def neighbor_ids(orig, window):
    base = int(orig)
    ids = []
    for d in range(1, window + 1):
        if base + d > 0:
            ids.append(str(base + d))
        if base - d > 0:
            ids.append(str(base - d))
    return ids

def scan(session, url, args):
    findings = []
    m = ID_PATTERN.search(url)
    if not m:
        return {"error": "no numeric ID parameter found (?id=123 style). Add one, or use a URL from your authenticated session."}
    prefix, param, orig_id = m.group(1), m.group(2), m.group(3)

    try:
        r0 = session.get(url, timeout=args.timeout, allow_redirects=True)
    except requests.RequestException as e:
        return {"error": f"baseline failed: {e}"}
    base = fingerprint(r0.text)
    base.update({"status": r0.status_code, "url": url, "id": orig_id})

    for test_id in neighbor_ids(orig_id, args.window):
        test_url = url.replace(f"{prefix}{param}={orig_id}", f"{prefix}{param}={test_id}", 1)
        try:
            r = session.get(test_url, timeout=args.timeout, allow_redirects=True)
        except requests.RequestException as e:
            findings.append({"id": test_id, "error": str(e)})
            continue
        fp = fingerprint(r.text)
        same_content = fp["sha256"] == base["sha256"]
        similar = (min(fp["length"], base["length"]) / max(fp["length"], base["length"]) > 0.9) if base["length"] else False
        verdict = "ok"
        if r.status_code == 200 and not same_content and similar:
            verdict = "potential-idor"
        elif r.status_code == 200 and not same_content:
            verdict = "differs-check-manually"
        elif r.status_code in (401, 403):
            verdict = "access-denied"
        findings.append({"id": test_id, "url": test_url, "status": r.status_code,
                         "length": fp["length"], "same_content": same_content, "verdict": verdict})
        if args.delay:
            time.sleep(args.delay)

    return {"tool": "TBH-IDOR", "version": VERSION, "target": url,
            "baseline": base, "findings": findings}

def main():
    parser = argparse.ArgumentParser(description=f"TBH-IDOR v{VERSION} - access-control helper")
    parser.add_argument("-u", "--url", help="authenticated URL containing ?id=NNN")
    parser.add_argument("--targets", help="file with one URL per line (multi-target)")
    parser.add_argument("--window", type=int, default=2, help="neighbor IDs to try each direction (default 2)")
    parser.add_argument("--proxy", help="e.g. http://127.0.0.1:8080 (Burp)")
    parser.add_argument("--cookie", help="Cookie header value (your own session)")
    parser.add_argument("-H", "--header", action="append", help="extra header, repeatable")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--json", help="save JSON report")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"TBH-IDOR {VERSION}")
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
                           {"tool": "TBH-IDOR", "version": VERSION,
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
    print(color("91", "[!] Use ONLY accounts you own. Accessing other users' objects is a crime.", use_color))
    print(f"[*] Scanning {args.url} (±{args.window} IDs)")
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
        v = f.get("verdict")
        if v == "potential-idor":
            vuln += 1
            print(color("91", f"[?] id={f['id']} -> {f['status']} len={f['length']} (same size, different content) - verify with 2nd account", use_color))
        elif v == "differs-check-manually":
            print(color("93", f"[?] id={f['id']} -> {f['status']} len={f['length']} (differs from baseline)", use_color))
        elif v == "access-denied":
            print(color("92", f"[✓] id={f['id']} -> {f['status']} (access control present)", use_color))
        elif "error" in f:
            print(color("90", f"[-] id={f.get('id')}: {f['error']}", use_color))

    if args.json:
        report["summary"] = {"potential_idor": vuln}
        try:
            with open(args.json, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"[✓] JSON: {args.json}")
        except OSError as e:
            print(color("91", f"[!] cannot write JSON: {e}", use_color), file=sys.stderr)
            sys.exit(2)

    if vuln:
        print(color("91", f"[!] {vuln} candidate(s) - confirm with a second account YOU own before reporting", use_color))
        sys.exit(1)
    print(color("92", "[✓] No IDOR candidates (or access control correctly denies)", use_color))
    sys.exit(0)

if __name__ == "__main__":
    main()
