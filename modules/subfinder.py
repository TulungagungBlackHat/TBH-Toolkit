#!/usr/bin/env python3
"""TBH-SubFinder v3 - Subdomain enumerator with CNAME takeover hints (authorized testing only)."""
import argparse, json, os, random, socket, string, sys, struct, time
from concurrent.futures import ThreadPoolExecutor

try:
    import requests
except ImportError:
    print("[!] requests required: pip install requests", file=sys.stderr)
    sys.exit(2)

VERSION = "3.0"
REPO = "https://github.com/TulungagungBlackHat/TBH-SubFinder"

def banner():
    if os.environ.get("NO_COLOR"):
        return ""
    return ("\033[91m╔════════════════════════════════════╗\n"
            "║ \033[97mTBH-SubFinder v3\033[91m - CNAME/Takeover  ║\n"
            "║ \033[90mTulungagung Black Hat | uchil404 \033[91m║\n"
            "╚════════════════════════════════════╝\033[0m")

def color(code, text, enabled=True):
    return f"\033[{code}m{text}\033[0m" if enabled else text

WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "blog", "shop", "m", "mobile", "dev",
    "test", "staging", "beta", "vpn", "secure", "portal", "app", "cdn", "ns1", "ns2",
    "smtp", "pop", "imap", "demo", "old", "new", "beta2", "dashboard", "cpanel",
    "webmail", "git", "gitlab", "jenkins", "ci", "status", "docs", "support", "help",
    "cdn2", "static", "media", "img", "images", "assets", "files", "download",
    "backend", "internal", "intranet", "hr", "pay", "billing", "crm", "erp",
    "grafana", "kibana", "elastic", "db", "mysql", "redis", "cache", "proxy",
    "sandbox", "uat", "qa", "load", "edge", "origin", "ws", "socket", "realtime",
]

# CNAME suffixes -> service, and whether a parked/unclaimed page is common
TAKEOVER_SERVICES = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "herokussl.com": "Heroku",
    "amazonaws.com": "AWS/S3/CloudFront",
    "cloudfront.net": "AWS CloudFront",
    "azurewebsites.net": "Azure App Service",
    "azure.net": "Azure",
    "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob",
    "shopify.com": "Shopify",
    "fastly.net": "Fastly",
    "edgekey.net": "Akamai",
    "unbounce.com": "Unbounce",
    "hubspot.net": "HubSpot",
    "wordpress.com": "WordPress.com",
    "ghost.io": "Ghost",
    "surge.sh": "Surge",
    "netlify.com": "Netlify",
    "zendesk.com": "Zendesk",
    "readthedocs.io": "ReadTheDocs",
    "pantheon.io": "Pantheon",
    "wpengine.com": "WP Engine",
    "statuspage.io": "Statuspage",
}

def dns_query(name, qtype, server="8.8.8.8", timeout=3.0):
    """Minimal DNS client over UDP. qtype: 1=A, 5=CNAME, 16=TXT."""
    tid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.strip(".").split(".")) + b"\x00"
    q += struct.pack(">HH", qtype, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(header + q, (server, 53))
        data, _ = sock.recvfrom(4096)
    except (socket.timeout, OSError):
        return []
    # skip header + question, parse answers crudely
    answers = []
    try:
        qd = struct.unpack(">H", data[4:6])[0]
        an = struct.unpack(">H", data[6:8])[0]
        i = 12
        for _ in range(qd):
            while data[i] != 0:
                i += 1 + data[i]
            i += 5
        for _ in range(an):
            if data[i] & 0xC0 == 0xC0:
                i += 2
            else:
                while data[i] != 0:
                    i += 1 + data[i]
                i += 1
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[i:i + 10])
            i += 10
            rdata = data[i:i + rdlen]
            i += rdlen
            if rtype == 5:  # CNAME
                labels, j = [], i - rdlen
                while data[j] != 0:
                    if data[j] & 0xC0 == 0xC0:
                        j = struct.unpack(">H", data[j:j + 2])[0] & 0x3FFF
                        continue
                    labels.append(data[j + 1:j + 1 + data[j]].decode("utf-8", "replace"))
                    j += 1 + data[j]
                answers.append(".".join(labels))
    except (struct.error, IndexError, UnicodeDecodeError):
        pass
    finally:
        sock.close()
    return answers

def cname_chain(host):
    chain, seen = [], set()
    current = host
    for _ in range(6):
        if current in seen:
            break
        seen.add(current)
        cnames = dns_query(current, 5)
        if not cnames:
            break
        current = cnames[0]
        chain.append(current)
    return chain

def takeover_hint(chain):
    for c in chain:
        for suffix, service in TAKEOVER_SERVICES.items():
            if c.endswith(suffix) or f".{suffix}." in f".{c}.":
                return service, c
    return None, None

def check_host(sub, domain, args):
    host = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return None
    chain = cname_chain(host)
    service, target = takeover_hint(chain)
    result = {"host": host, "ip": ip, "cname": chain, "http": None,
              "takeover_service": service, "takeover_target": target}
    if not args.dns_only:
        try:
            s = requests.Session()
            s.headers["User-Agent"] = f"TBH-SubFinder/{VERSION} (+{REPO})"
            if args.proxy:
                s.proxies = {"http": args.proxy, "https": args.proxy}
            r = s.get(f"https://{host}", timeout=args.timeout, allow_redirects=True, verify=False)
            result["http"] = {"status": r.status_code, "length": len(r.text),
                              "title": (r.text.split("<title>", 1)[1].split("</title>", 1)[0][:80]
                                        if "<title>" in r.text else "")}
        except requests.RequestException:
            result["http"] = "no-http"
        if args.delay:
            time.sleep(args.delay)
    return result

def main():
    parser = argparse.ArgumentParser(description=f"TBH-SubFinder v{VERSION}")
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-w", "--wordlist", help="custom wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=20)
    parser.add_argument("--dns-only", action="store_true", help="skip HTTP probing")
    parser.add_argument("--proxy", help="proxy for HTTP probe, e.g. http://127.0.0.1:8080")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--json", help="save JSON report")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"TBH-SubFinder {VERSION}")
    args = parser.parse_args()
    print(banner())

    use_color = not args.no_color and not os.environ.get("NO_COLOR")
    print(color("91", "[!] Authorized scopes only. Brute-forcing is noisy.", use_color))

    wordlist = WORDLIST
    if args.wordlist:
        try:
            with open(args.wordlist) as fh:
                wordlist = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as e:
            print(color("91", f"[!] cannot read wordlist: {e}", use_color), file=sys.stderr)
            sys.exit(2)

    # wildcard DNS detection
    probe = "tbhwildcard" + "".join(random.choices(string.ascii_lowercase, k=8))
    wildcard = None
    try:
        wildcard = socket.gethostbyname(f"{probe}.{args.domain}")
        print(color("93", f"[?] Wildcard DNS suspected: {probe}.{args.domain} -> {wildcard} (results may be polluted)", use_color))
    except socket.gaierror:
        pass

    print(f"[*] {args.domain} | {len(wordlist)} words | {args.threads} threads")
    found = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        for r in ex.map(lambda s: check_host(s, args.domain, args), wordlist):
            if r:
                found.append(r)
                flag = ""
                if r["takeover_service"]:
                    flag = color("91", f" [TAKEOVER? {r['takeover_service']}]", use_color)
                status = r["http"]["status"] if isinstance(r["http"], dict) else r["http"]
                print(color("92", f"[FOUND] {r['host']} -> {r['ip']} [{status}]{flag}", use_color))
                if r["takeover_service"]:
                    print(f"    CNAME -> {r['takeover_target']} - verify unclaimed state manually (High)")

    summary = {"found": len(found), "takeover_hints": sum(1 for x in found if x["takeover_service"]),
               "wildcard": wildcard}
    print(f"\n[✓] Found {summary['found']} | Takeover hints: {summary['takeover_hints']}")
    if args.json:
        report = {"tool": "TBH-SubFinder", "version": VERSION, "target": args.domain,
                  "summary": summary, "findings": found}
        try:
            with open(args.json, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"[✓] JSON: {args.json}")
        except OSError as e:
            print(color("91", f"[!] cannot write JSON: {e}", use_color), file=sys.stderr)
            sys.exit(2)

    sys.exit(1 if summary["takeover_hints"] else 0)

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    main()
