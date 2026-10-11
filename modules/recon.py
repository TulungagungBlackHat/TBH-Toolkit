#!/usr/bin/env python3
"""TBH-Recon v3 - Web reconnaissance with JSON/HTML reports (authorized testing only)."""
import argparse, json, os, socket, ssl, sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("[!] requests required: pip install requests", file=sys.stderr)
    sys.exit(2)

VERSION = "3.1"
REPO = "https://github.com/TulungagungBlackHat/TBH-Recon"

def banner():
    if os.environ.get("NO_COLOR"):
        return ""
    return ("\033[91m╔════════════════════════════════════╗\n"
            "║ \033[97mTBH-Recon v3\033[91m - Full First Pass     \033[91m║\n"
            "║ \033[90mTulungagung Black Hat | uchil404 \033[91m║\n"
            "╚════════════════════════════════════╝\033[0m")

def color(code, text, enabled=True):
    return f"\033[{code}m{text}\033[0m" if enabled else text

PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]
SUBS = ["www", "mail", "api", "admin", "dev", "test", "staging", "app"]
IMPORTANT_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
                     "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]

def build_session(args):
    s = requests.Session()
    s.headers["User-Agent"] = f"TBH-Recon/{VERSION} (+{REPO})"
    if args.cookie:
        s.headers["Cookie"] = args.cookie
    for h in args.header or []:
        name, _, val = h.partition(":")
        if val:
            s.headers[name.strip()] = val.strip()
    if args.proxy:
        s.proxies = {"http": args.proxy, "https": args.proxy}
    return s

def check_headers(session, url, args):
    r = session.get(url, timeout=args.timeout)
    missing = [h for h in IMPORTANT_HEADERS if h not in r.headers]
    return {"status": r.status_code, "server": r.headers.get("Server", ""),
            "powered_by": r.headers.get("X-Powered-By", ""),
            "missing": missing, "headers": dict(r.headers)}

def check_ssl(domain, args):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(args.timeout)
            s.connect((domain, 443))
            cert = s.getpeercert()
        expire = cert.get("notAfter")
        issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "Unknown")
        days = (datetime.strptime(expire, "%b %d %H:%M:%S %Y %Z")
                .replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
        return {"issuer": issuer, "expire": expire, "days": days}
    except Exception as e:
        return {"error": str(e)}

def port_scan(ip, ports, timeout):
    open_ports = []

    def probe(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout if timeout <= 2 else 1.0)
        try:
            if s.connect_ex((ip, port)) == 0:
                return port
        except OSError:
            pass
        finally:
            s.close()
        return None

    with ThreadPoolExecutor(max_workers=30) as ex:
        for p in ex.map(probe, ports):
            if p:
                open_ports.append({"port": p})
    return open_ports

def subdomain_enum(domain):
    found = []
    for sub in SUBS:
        try:
            found.append({"host": f"{sub}.{domain}", "ip": socket.gethostbyname(f"{sub}.{domain}")})
        except socket.gaierror:
            pass
    return found

def build_findings(report):
    findings = []
    for h in report.get("headers", {}).get("missing", []):
        findings.append({"severity": "Low", "title": f"Missing {h}", "fix": f"Set {h} header"})
    if report.get("headers", {}).get("powered_by"):
        findings.append({"severity": "Info", "title": "Technology disclosed (X-Powered-By)",
                         "detail": report["headers"]["powered_by"], "fix": "Suppress header"})
    ssl_info = report.get("ssl", {})
    if isinstance(ssl_info.get("days"), int) and ssl_info["days"] < 30:
        findings.append({"severity": "Medium", "title": f"SSL expires in {ssl_info['days']} days",
                         "fix": "Renew certificate"})
    risky = {6379: "Redis", 27017: "MongoDB", 2375: "Docker API"}
    for p in report.get("ports", []):
        if p["port"] in risky:
            findings.append({"severity": "High", "title": f"{risky[p['port']]} port {p['port']} open",
                             "fix": "Restrict exposure / require auth"})
    return findings

def write_html(report, path):
    html = f"""<html><head><title>TBH-Recon {report['target']}</title></head>
<body style="font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px">
<h1 style="color:#ff0000">TBH-Recon v{VERSION} - {report['target']} ({report['ip']})</h1>
<p>Time: {report['time']}</p>
<h2>Findings</h2><pre>{json.dumps(report.get('findings', []), indent=2)}</pre>
<h2>Raw report</h2><pre>{json.dumps({k: v for k, v in report.items() if k != 'findings'}, indent=2)}</pre>
<p>Generated by TBH-Recon v{VERSION} - Tulungagung Black Hat</p></body></html>"""
    with open(path, "w") as fh:
        fh.write(html)

def read_targets(path):
    targets = []
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    except OSError as e:
        print(f"[!] cannot read targets file: {e}", file=sys.stderr)
    return targets

def recon_one(raw_url, args, use_color):
    url = raw_url if "://" in raw_url else "https://" + raw_url
    domain = urlparse(url).hostname or urlparse(url).netloc
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        print(color("91", f"[!] cannot resolve {domain}, skipped", use_color), file=sys.stderr)
        return None

    print(color("96", f"[*] {domain} ({ip})", use_color))
    session = build_session(args)
    report = {"tool": "TBH-Recon", "version": VERSION, "target": domain, "ip": ip, "url": url,
              "time": str(datetime.now(timezone.utc))}

    try:
        report["headers"] = check_headers(session, url, args)
        print(color("92", f"[+] Status {report['headers']['status']} | "
                          f"Missing: {', '.join(report['headers']['missing']) or 'none'}", use_color))
    except requests.RequestException as e:
        report["headers"] = {"error": str(e)}
        print(color("90", f"[-] Headers: {e}", use_color))

    if args.ssl:
        report["ssl"] = check_ssl(domain, args)
        print(color("92", f"[+] SSL: {report['ssl']}", use_color))
    if args.ports:
        report["ports"] = port_scan(ip, PORTS, args.timeout)
        print(color("92", f"[+] Ports: {[p['port'] for p in report['ports']]}", use_color))
    if args.subdomain:
        report["subdomains"] = subdomain_enum(domain)
        print(color("92", f"[+] Subdomains: {[s['host'] for s in report['subdomains']]}", use_color))

    report["findings"] = build_findings(report)
    for f in report["findings"]:
        sev = {"High": "91", "Medium": "93", "Low": "90", "Info": "90"}[f["severity"]]
        print(color(sev, f"[{f['severity']}] {f['title']} -> {f['fix']}", use_color))
    return report

def main():
    parser = argparse.ArgumentParser(description=f"TBH-Recon v{VERSION}")
    parser.add_argument("-u", "--url", help="target URL")
    parser.add_argument("--targets", help="file with one URL per line (multi-target)")
    parser.add_argument("--ssl", action="store_true", help="SSL certificate check")
    parser.add_argument("-p", "--ports", action="store_true", help="port scan")
    parser.add_argument("-s", "--subdomain", action="store_true", help="subdomain enumeration")
    parser.add_argument("--proxy", help="e.g. http://127.0.0.1:8080")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("-H", "--header", action="append", help="extra header, repeatable")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--json", help="save JSON report")
    parser.add_argument("--html", help="save HTML report (single target only)")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"TBH-Recon {VERSION}")
    args = parser.parse_args()
    if not args.url and not args.targets:
        parser.error("-u or --targets is required")
    print(banner())

    use_color = not args.no_color and not os.environ.get("NO_COLOR")
    print(color("91", "[!] Authorized targets only.", use_color))
    targets = ([args.url] if args.url else []) + (read_targets(args.targets) if args.targets else [])

    reports = []
    for i, t in enumerate(targets):
        if i > 0 and args.targets:
            print(color("96", "-" * 40, use_color))
        r = recon_one(t, args, use_color)
        if r:
            reports.append(r)

    if not reports:
        sys.exit(2)

    if args.json:
        data = (reports[0] if len(reports) == 1 else
                {"tool": "TBH-Recon", "version": VERSION,
                 "summary": {"targets": len(reports),
                             "findings": sum(len(r["findings"]) for r in reports)},
                 "targets": reports})
        try:
            with open(args.json, "w") as fh:
                json.dump(data, fh, indent=2)
            print(f"[✓] JSON: {args.json}")
        except OSError as e:
            print(color("91", f"[!] cannot write JSON: {e}", use_color), file=sys.stderr)
            sys.exit(2)
    if args.html:
        if len(reports) > 1:
            print(color("93", "[!] --html is single-target; skipped for multi-target scan", use_color))
        else:
            try:
                write_html(reports[0], args.html)
                print(f"[✓] HTML: {args.html}")
            except OSError as e:
                print(color("91", f"[!] cannot write HTML: {e}", use_color), file=sys.stderr)
                sys.exit(2)

    print(color("92", "[✓] Done", use_color))
    sys.exit(1 if any(f["severity"] in ("High", "Medium")
                      for r in reports for f in r["findings"]) else 0)

if __name__ == "__main__":
    main()
