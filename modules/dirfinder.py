#!/usr/bin/env python3
"""TBH-DirFinder v3 - Content discovery with soft-404 filtering (authorized testing only)."""
import argparse, json, os, sys, time
from concurrent.futures import ThreadPoolExecutor

try:
    import requests
except ImportError:
    print("[!] requests required: pip install requests", file=sys.stderr)
    sys.exit(2)

VERSION = "3.1"
REPO = "https://github.com/TulungagungBlackHat/TBH-DirFinder"

def banner():
    if os.environ.get("NO_COLOR"):
        return ""
    return ("\033[91m╔════════════════════════════════════╗\n"
            "║ \033[97mTBH-DirFinder v3\033[91m - Soft404 Filter  ║\n"
            "║ \033[90mTulungagung Black Hat | uchil404 \033[91m║\n"
            "╚════════════════════════════════════╝\033[0m")

def color(code, text, enabled=True):
    return f"\033[{code}m{text}\033[0m" if enabled else text

PATHS = [
    ".git", ".git/config", ".git/HEAD", ".env", ".env.backup", ".DS_Store",
    "robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt",
    "admin", "admin/", "login", "administrator", "dashboard", "wp-admin",
    "api", "api/", "api/v1", "api/docs", "swagger", "swagger.json", "openapi.json",
    "graphql", "graphiql", "phpinfo.php", "info.php", "test", "debug",
    "backup", "backup.zip", "backup.tar.gz", "db.sql", "dump.sql", "config.php",
    "config.json", "composer.json", "package.json", ".htaccess", "web.config",
    "server-status", "server-info", ".aws/credentials", "id_rsa", "wp-config.php.bak",
    "actuator", "actuator/health", "metrics", "health", "status",
    "console", "shell", "phpmyadmin", "adminer.php",
]
BYPASS_HEADERS = [
    {"X-Original-URL": None},
    {"X-Rewrite-URL": None},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
]
SENSITIVE = {".git", ".git/config", ".git/HEAD", ".env", ".env.backup", ".aws/credentials",
             "id_rsa", "db.sql", "dump.sql", "wp-config.php.bak", "config.php"}

def build_session(args):
    s = requests.Session()
    s.headers["User-Agent"] = f"TBH-DirFinder/{VERSION} (+{REPO})"
    if args.cookie:
        s.headers["Cookie"] = args.cookie
    for h in args.header or []:
        name, _, val = h.partition(":")
        if val:
            s.headers[name.strip()] = val.strip()
    if args.proxy:
        s.proxies = {"http": args.proxy, "https": args.proxy}
    return s

def probe(session, url, args):
    try:
        r = session.get(url, timeout=args.timeout, allow_redirects=False)
        return {"status": r.status_code, "length": len(r.content), "headers": dict(r.headers)}
    except requests.RequestException as e:
        return {"error": str(e)}

def check(session, base, path, args, soft404):
    url = f"{base.rstrip('/')}/{path.lstrip('/')}"
    out = probe(session, url, args)
    if "error" in out:
        return None
    status, length = out["status"], out["length"]
    if status not in (200, 204, 301, 302, 401, 403):
        return None
    # soft-404 filter: a "found" response almost identical to the missing-page baseline
    if soft404 and status == soft404["status"] and abs(length - soft404["length"]) < soft404["tolerance"]:
        return None
    if args.status and status not in args.status:
        return None
    bypass = None
    if args.bypass and status in (401, 403):
        for extra in BYPASS_HEADERS:
            h = dict(extra)
            key = list(h)[0]
            h[key] = h[key] if h[key] is not None else f"/{path}"
            try:
                r = session.get(url, timeout=args.timeout, headers=h, allow_redirects=False)
                if r.status_code == 200:
                    bypass = h
                    status, length = 200, len(r.content)
                    break
            except requests.RequestException:
                continue
    if args.delay:
        time.sleep(args.delay)
    return {"path": path, "url": url, "status": status, "length": length,
            "sensitive": path in SENSITIVE or path.split("/")[-1] in SENSITIVE,
            "bypass": bypass, "location": out.get("headers", {}).get("Location", "")}

def main():
    parser = argparse.ArgumentParser(description=f"TBH-DirFinder v{VERSION}")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-w", "--wordlist", help="custom wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=15)
    parser.add_argument("--status", type=int, nargs="+", help="only report these statuses")
    parser.add_argument("--bypass", action="store_true", help="try 403-bypass header variants on 401/403")
    parser.add_argument("--depth", type=int, default=0,
                        help="recurse into discovered directories (0 = no recursion)")
    parser.add_argument("--max-paths", type=int, default=500,
                        help="total request budget across all recursion levels")
    parser.add_argument("--proxy", help="e.g. http://127.0.0.1:8080")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("-H", "--header", action="append", help="extra header, repeatable")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--json", help="save JSON report")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"TBH-DirFinder {VERSION}")
    args = parser.parse_args()
    print(banner())

    use_color = not args.no_color and not os.environ.get("NO_COLOR")
    print(color("91", "[!] Authorized scopes only.", use_color))

    paths = PATHS
    if args.wordlist:
        try:
            with open(args.wordlist) as fh:
                paths = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as e:
            print(color("91", f"[!] cannot read wordlist: {e}", use_color), file=sys.stderr)
            sys.exit(2)

    session = build_session(args)
    base = args.url.rstrip("/")

    # soft-404 baseline: random missing path
    miss = probe(session, f"{base}/tbhdefinitelymissing{''.join(str(time.time()).split('.'))}", args)
    soft404 = None
    if isinstance(miss, dict) and "status" in miss:
        soft404 = {"status": miss["status"], "length": miss["length"], "tolerance": max(25, miss["length"] // 50)}

    print(f"[*] {base} | {len(paths)} paths | {args.threads} threads"
          + (f" | depth={args.depth} budget={args.max_paths}" if args.depth else "")
          + (" | 403-bypass on" if args.bypass else ""))
    found = []
    queue = [(base, "")]
    seen = {base}
    budget = args.max_paths
    while queue and budget > 0:
        root, rel = queue.pop(0)
        batch = paths[:budget]
        budget -= len(batch)
        if rel:
            print(color("96", f"[*] recursing: {root}", use_color))
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            for r in ex.map(lambda p: check(session, root, p, args, soft404), batch):
                if not r:
                    continue
                if rel:
                    r["path"] = f"{rel}/{r['path']}"
                    r["root"] = root
                found.append(r)
                tag = color("91", " [SENSITIVE]", use_color) if r["sensitive"] else ""
                tag += color("92", " [BYPASS]", use_color) if r["bypass"] else ""
                print(color("93" if r["status"] != 200 else "91",
                            f"[FOUND] {r['status']} {r['url']} ({r['length']}b){tag}", use_color))
                last = r["path"].split("/")[-1]
                is_dir = ("." not in last and not r["sensitive"] and
                          (r["status"] == 200 or
                           (r["status"] in (301, 302) and
                            (r["location"].startswith(base) or r["location"].startswith("/")))))
                if (args.depth and is_dir and r["url"].rstrip("/") not in seen):
                    seen.add(r["url"].rstrip("/"))
                    depth_level = r["path"].count("/")
                    if depth_level < args.depth:
                        queue.append((r["url"].rstrip("/"), r["path"]))

    sensitive = sum(1 for r in found if r["sensitive"])
    print(f"\n[✓] Found {len(found)} | sensitive: {sensitive}")
    if args.json:
        report = {"tool": "TBH-DirFinder", "version": VERSION, "target": base,
                  "summary": {"found": len(found), "sensitive": sensitive},
                  "findings": found}
        try:
            with open(args.json, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"[✓] JSON: {args.json}")
        except OSError as e:
            print(color("91", f"[!] cannot write JSON: {e}", use_color), file=sys.stderr)
            sys.exit(2)

    sys.exit(1 if sensitive else (1 if found else 0))

if __name__ == "__main__":
    main()
