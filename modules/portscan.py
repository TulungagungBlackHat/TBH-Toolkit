#!/usr/bin/env python3
"""TBH-PortScanner v3 - Multithreaded TCP scanner with banner grab (authorized testing only)."""
import argparse, json, socket, sys, time
from concurrent.futures import ThreadPoolExecutor

VERSION = "3.1"
REPO = "https://github.com/TulungagungBlackHat/TBH-PortScanner"

def banner():
    if os_environ_no_color():
        return ""
    return ("\033[91m╔════════════════════════════════════╗\n"
            "║ \033[97mTBH-PortScanner v3\033[91m - Top100+Banner  ║\n"
            "║ \033[90mTulungagung Black Hat | uchil404 \033[91m║\n"
            "╚════════════════════════════════════╝\033[0m")

def os_environ_no_color():
    import os
    return bool(os.environ.get("NO_COLOR"))

def color(code, text, enabled=True):
    return f"\033[{code}m{text}\033[0m" if enabled else text

TOP100 = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 389, 427, 443, 444, 445, 465, 513, 514, 515,
    543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027,
    1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
    2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5001, 5003, 5009, 5050,
    5060, 5101, 5357, 5432, 5631, 5666, 5900, 5988, 5989, 6000, 6001, 6646,
    7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
]
CVE_HINTS = {
    21: "FTP: check anon login, CVE-2018-10933 (libssh)",
    22: "SSH: banner-grab versions, weak ciphers",
    23: "Telnet: cleartext - usually reportable if exposed",
    25: "SMTP: open relay test (VRFY/EXPN)",
    53: "DNS: zone transfer attempt (AXFR)",
    80: "HTTP: run TBH-Recon / TBH-AllScan next",
    110: "POP3: cleartext credentials",
    139: "NetBIOS: enumeration, EternalBlue-era risks",
    143: "IMAP: cleartext credentials",
    443: "HTTPS: certificate + TLS check via TBH-Recon",
    445: "SMB: MS17-010 EternalBlue check (authorized only!)",
    1433: "MSSQL: default creds, xp_cmdshell exposure",
    2375: "Docker API: unauthenticated - Critical",
    3306: "MySQL: remote root, weak grants",
    3389: "RDP: BlueKeep CVE-2019-0708, NLA status",
    5432: "PostgreSQL: pg_hba exposure",
    5900: "VNC: auth bypass, CVE-2019-15691 family",
    6379: "Redis: unauthenticated - usually Critical",
    8080: "HTTP-Alt: proxy/admin panels common",
    8443: "HTTPS-Alt: admin panels common",
    9200: "Elasticsearch: unauthenticated cluster",
    11211: "Memcached: UDP amplification, data leak",
    27017: "MongoDB: unauthenticated - usually Critical",
}

def scan_port(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) == 0:
            banner_bytes = b""
            try:
                s.settimeout(2)
                banner_bytes = s.recv(256)
            except (socket.timeout, OSError):
                pass
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            return {"port": port, "open": True, "service": service,
                    "hint": CVE_HINTS.get(port, ""),
                    "banner": banner_bytes.decode("utf-8", "replace").strip()[:120]}
    except OSError:
        pass
    finally:
        s.close()
    return None

def parse_ports(spec):
    if spec == "top100":
        return TOP100
    if "-" in spec:
        a, b = spec.split("-", 1)
        return list(range(int(a), int(b) + 1))
    if "," in spec:
        return [int(p) for p in spec.split(",")]
    return [int(spec)]

def scan_host(target, ports, args, use_color):
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(color("91", f"[!] cannot resolve {target}, skipped", use_color), file=sys.stderr)
        return None

    print(f"[*] {target} ({ip}) | {len(ports)} ports | {args.threads} threads")
    start = time.time()
    open_ports = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        for r in ex.map(lambda p: scan_port(ip, p, args.timeout), ports):
            if r:
                open_ports.append(r)
                hint = color("90", f"  {r['hint']}", use_color) if r["hint"] else ""
                banner_str = f"  banner={r['banner']!r}" if r["banner"] else ""
                print(color("91", f"[OPEN] {r['port']}/{r['service']}{banner_str}", use_color) + hint)
    elapsed = round(time.time() - start, 2)
    print(f"[✓] {target}: {len(open_ports)} open in {elapsed}s")
    return {"target": target, "ip": ip, "elapsed": elapsed,
            "summary": {"open": len(open_ports)}, "findings": open_ports}

def main():
    import os
    parser = argparse.ArgumentParser(description=f"TBH-PortScanner v{VERSION}")
    parser.add_argument("-t", "--target", help="host or IP")
    parser.add_argument("--targets", help="file with one host per line (multi-target)")
    parser.add_argument("-p", "--ports", default="top100", help="top100 | 1-1000 | 80,443,8080")
    parser.add_argument("-T", "--threads", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=1.0, help="connect timeout seconds")
    parser.add_argument("--json", help="save JSON report")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"TBH-PortScanner {VERSION}")
    args = parser.parse_args()
    if not args.target and not args.targets:
        parser.error("-t or --targets is required")
    print(banner())

    use_color = not args.no_color and not os.environ.get("NO_COLOR")
    print(color("91", "[!] Authorized targets only.", use_color))

    try:
        ports = parse_ports(args.ports)
    except ValueError:
        print(color("91", "[!] bad --ports value", use_color), file=sys.stderr)
        sys.exit(2)

    targets = ([args.target] if args.target else [])
    if args.targets:
        try:
            with open(args.targets) as fh:
                targets += [line.strip() for line in fh
                            if line.strip() and not line.strip().startswith("#")]
        except OSError as e:
            print(color("91", f"[!] cannot read targets file: {e}", use_color), file=sys.stderr)
            sys.exit(2)

    reports = []
    for i, t in enumerate(targets):
        if i > 0 and args.targets:
            print(color("96", "-" * 40, use_color))
        r = scan_host(t, ports, args, use_color)
        if r:
            reports.append(r)

    if not reports:
        sys.exit(2)

    if args.json:
        report = ({"tool": "TBH-PortScanner", "version": VERSION, **reports[0]}
                  if len(reports) == 1 else
                  {"tool": "TBH-PortScanner", "version": VERSION,
                   "summary": {"targets": len(reports),
                               "open": sum(r["summary"]["open"] for r in reports)},
                   "targets": reports})
        try:
            with open(args.json, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"[✓] JSON: {args.json}")
        except OSError as e:
            print(color("91", f"[!] cannot write JSON: {e}", use_color), file=sys.stderr)
            sys.exit(2)

    sys.exit(1 if any(r["findings"] for r in reports) else 0)

if __name__ == "__main__":
    main()
