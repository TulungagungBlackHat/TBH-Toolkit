#!/usr/bin/env python3
"""TBH-CLI v3 - Bug bounty interactive menu, 34 real modules (authorized testing only)."""
import argparse, base64, json, os, re, socket, ssl, sys, time, urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("[!] requests required: pip install requests", file=sys.stderr)
    sys.exit(2)

VERSION = "3.2"
REPO = "https://github.com/TulungagungBlackHat/TBH-CLI"

S = None
ARGS = None
URL = None
DOMAIN = None
IP = None
BASE = None
BASELINE = {}
FINDINGS = []
USE_COLOR = True

def banner():
    if os.environ.get("NO_COLOR"):
        return ""
    return ("\033[91m╔════════════════════════════════════╗\n"
            "║ \033[97mTBH-CLI v3\033[91m - 34 Real Modules       \033[91m║\n"
            "║ \033[90mTulungagung Black Hat | uchil404 \033[91m║\n"
            "╚════════════════════════════════════╝\033[0m")

def c(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

def emit(module, severity, title, detail="", fix=""):
    f = {"module": module, "severity": severity, "title": title, "detail": str(detail), "fix": fix}
    FINDINGS.append(f)
    colors = {"High": "91", "Medium": "93", "Low": "90", "Info": "96"}
    print(f"  {c(colors[severity], f'[{severity}] {title}')}"
          + (f" {c('90', detail)}" if detail else "")
          + (f" -> {c('90', fix)}" if fix else ""))

def ok(msg):
    print(f"  {c('92', '[✓] ' + msg)}")

def skip(msg):
    print(f"  {c('90', '[-] ' + msg)}")

def err(msg):
    print(f"  {c('91', '[-] ' + msg)}")

def build_session():
    s = requests.Session()
    s.headers["User-Agent"] = f"TBH-CLI/{VERSION} (+{REPO})"
    if ARGS.cookie:
        s.headers["Cookie"] = ARGS.cookie
    for h in ARGS.header or []:
        name, _, val = h.partition(":")
        if val:
            s.headers[name.strip()] = val.strip()
    if ARGS.proxy:
        s.proxies = {"http": ARGS.proxy, "https": ARGS.proxy}
    return s

def get(url, **kw):
    kw.setdefault("timeout", ARGS.timeout)
    return S.get(url, **kw)

def post(url, **kw):
    kw.setdefault("timeout", ARGS.timeout)
    return S.post(url, **kw)

def baseline_for(u):
    if u not in BASELINE:
        try:
            r = get(u, allow_redirects=True)
            BASELINE[u] = {"status": r.status_code, "len": len(r.content), "text": r.text}
        except requests.RequestException as e:
            BASELINE[u] = {"error": str(e)}
    return BASELINE[u]

def first_param():
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(URL).query, keep_blank_values=True)
    return next(iter(qs), None)

def inject(param, value, url=None):
    u = url or URL
    p = urllib.parse.urlparse(u)
    qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    param = ARGS.param or param or first_param() or "q"
    qs[param] = [value]
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(qs, doseq=True))), param

def probe_inject(base_param, payloads, marker_fn):
    last = None
    for pl in payloads:
        u, param = inject(base_param, pl)
        try:
            r = get(u, allow_redirects=False)
        except requests.RequestException as e:
            last = str(e)
            continue
        hit = marker_fn(r, pl)
        if hit:
            return hit, param, pl
    return None, None, None

MODULES = {}

def module(name, desc):
    def deco(fn):
        MODULES[name] = {"fn": fn, "desc": desc}
        return fn
    return deco

# ---------------- recon ----------------

@module("headers", "Security header audit")
def m_headers():
    try:
        r = get(URL)
    except requests.RequestException as e:
        err(f"headers: {e}")
        return
    important = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
                 "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]
    missing = [h for h in important if h not in r.headers]
    for h in missing:
        emit("headers", "Low", f"Missing {h}", f"HTTP {r.status_code}", f"Add {h} header")
    if not missing:
        ok(f"all {len(important)} security headers present")

@module("ports", "Top-15 port scan")
def m_ports():
    ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]
    def probe(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            if s.connect_ex((IP, p)) == 0:
                return p
        except OSError:
            pass
        finally:
            s.close()
        return None
    with ThreadPoolExecutor(max_workers=30) as ex:
        found = [p for p in ex.map(probe, ports) if p]
    interesting = {6379: ("Redis", "High"), 3306: ("MySQL", "Medium"), 5432: ("PostgreSQL", "Medium"),
                   445: ("SMB", "Medium"), 3389: ("RDP", "Medium"), 21: ("FTP", "Low"), 25: ("SMTP", "Low")}
    normal = []
    for p in found:
        if p in interesting:
            name, sev = interesting[p]
            emit("ports", sev, f"Open {p}/{name}", "", "Verify exposure")
        else:
            normal.append(p)
    if normal:
        print(f"  {c('90', f'[i] common ports open: {normal}')}")
    if not found:
        ok("no open ports in top-15 list")

@module("subdomains", "DNS subdomain enumeration")
def m_subdomains():
    found = []
    for sub in ["www", "mail", "api", "admin", "app", "dev", "test", "staging"]:
        try:
            found.append((f"{sub}.{DOMAIN}", socket.gethostbyname(f"{sub}.{DOMAIN}")))
        except socket.gaierror:
            pass
    for h, ip in found:
        emit("subdomains", "Info", f"Live {h}", ip, "Add to scope")
    if not found:
        ok("no subdomains found in wordlist")

@module("dirs", "Directory / sensitive file probe")
def m_dirs():
    base = URL.rstrip("/")
    paths = ["admin", ".env", ".git/config", "robots.txt", "backup.zip", ".well-known/security.txt"]
    b = baseline_for(URL)
    soft = b.get("text", "")[:200]
    def probe(path):
        try:
            r = get(f"{base}/{path}", allow_redirects=False)
            return path, r
        except requests.RequestException:
            return path, None
    with ThreadPoolExecutor(max_workers=6) as ex:
        for path, r in ex.map(probe, paths):
            if not r:
                continue
            if r.status_code in (200, 401, 403) and (r.text[:200] != soft or r.status_code != 200):
                sev = "High" if path in (".env", ".git/config", "backup.zip") else "Low"
                emit("dirs", sev, f"{r.status_code} /{path}", f"{len(r.content)}b", "Restrict access")

@module("host", "Host header injection")
def m_host():
    evil = "tbh-host-test.invalid"
    for hdr in ["X-Forwarded-Host", "Host"]:
        try:
            r = get(URL, headers={hdr: evil}, allow_redirects=False)
        except requests.RequestException as e:
            err(f"host: {e}")
            return
        if evil in r.text:
            emit("host", "Medium", f"Host reflected via {hdr}", evil, "Validate Host header")
            return
    ok("Host/X-Forwarded-Host not reflected")

# ---------------- vuln checks ----------------

@module("xss", "Reflected XSS (multi-payload)")
def m_xss():
    canary = "tbhxssCANARY1337"
    payloads = [f"<svg/onload=alert('{canary}')>", f"'\"><>{canary}", f"{canary}</title>"]
    hit, param, pl = probe_inject(None, payloads, lambda r, p: canary in r.text and p in r.text)
    if hit:
        emit("xss", "High", f"Reflection of unsanitized input in param '{param}'", pl, "Context-aware encoding")
    else:
        ok("no unencoded reflection")

@module("redirect", "Open redirect (param discovery)")
def m_redirect():
    marker = "tbh-redirect.invalid"
    param = None
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(URL).query, keep_blank_values=True)
    for k in ["next", "redirect", "url", "return", "dest", "continue"]:
        if k in qs:
            param = k
            break
    if not param:
        skip("no redirect-ish param in URL (use --param to force)")
        return
    u, _ = inject(param, f"https://{marker}/")
    try:
        r = get(u, allow_redirects=False)
    except requests.RequestException as e:
        err(f"redirect: {e}")
        return
    loc = r.headers.get("Location", "")
    if r.status_code in (301, 302, 303, 307, 308) and marker in loc:
        emit("redirect", "Medium", f"Open redirect via '{param}'", loc, "Strict allowlist")
    else:
        ok(f"'{param}' not redirecting externally")

@module("cors", "CORS misconfiguration")
def m_cors():
    origin = "https://tbh-cors-test.invalid"
    try:
        r = get(URL, headers={"Origin": origin})
    except requests.RequestException as e:
        err(f"cors: {e}")
        return
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    if acao == origin and acac.lower() == "true":
        emit("cors", "High", "Arbitrary origin + credentials", f"ACAO={acao} ACAC={acac}", "Allowlist origins")
    elif acao == origin:
        emit("cors", "Medium", "Arbitrary origin reflected", acao, "Allowlist origins")
    elif acao == "*" and acac.lower() == "true":
        emit("cors", "High", "Wildcard ACAO with credentials", f"ACAC={acac}", "Fix per spec")
    elif acao == "*":
        emit("cors", "Low", "Wildcard ACAO", "public API may be intended", "Confirm intent")
    else:
        ok("no CORS misconfig")

@module("sqli", "SQL injection (error-based)")
def m_sqli():
    markers = ["sql syntax", "you have an error in your sql", "mysql_", "ora-01756",
               "pg_query", "sqlite3.operationalerror", "unclosed quotation mark"]
    b = baseline_for(URL)
    base_err = any(mk in b.get("text", "").lower() for mk in markers)
    if base_err:
        skip("baseline already contains SQL errors (WAF/DB noisy)")
        return
    hit, param, pl = probe_inject(None, ["'", "\"", "1' OR '1'='1"],
                                  lambda r, p: any(mk in r.text.lower() for mk in markers))
    if hit:
        emit("sqli", "High", f"SQL error leaked in param '{param}'", pl, "Parameterized queries")
    else:
        ok("no SQL error leakage")

@module("ssrf", "SSRF via URL parameter")
def m_ssrf():
    param = None
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(URL).query, keep_blank_values=True)
    for k in ["url", "uri", "link", "dest", "next", "callback", "path", "feed"]:
        if k in qs:
            param = k
            break
    if not param:
        skip("no url-ish param (use --param to force)")
        return
    u, _ = inject(param, "http://169.254.169.254/latest/meta-data/")
    try:
        r = get(u, allow_redirects=False)
    except requests.RequestException as e:
        err(f"ssrf: {e}")
        return
    if "meta-data" in r.text.lower() or "ami-id" in r.text.lower():
        emit("ssrf", "High", f"Cloud metadata reachable via '{param}'", u, "Allowlist outbound URLs")
    else:
        ok(f"'{param}' does not fetch metadata")

@module("lfi", "Local file inclusion")
def m_lfi():
    b = baseline_for(URL)
    base_len = b.get("len", 0)
    payloads = ["../../../../etc/passwd", "....//....//etc/passwd", "..%2f..%2f..%2f..%2fetc/passwd"]
    hit, param, pl = probe_inject(None, payloads,
                                  lambda r, p: ("root:x:0:0" in r.text or "root:*:0:0" in r.text)
                                  and abs(len(r.content) - base_len) > 50)
    if hit:
        emit("lfi", "High", f"/etc/passwd readable via '{param}'", pl, "Canonicalize + allowlist paths")
    else:
        ok("no file disclosure")

@module("ssti", "Server-side template injection (dual-math)")
def m_ssti():
    hit, param, pl = probe_inject(None, ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
                                  lambda r, p: ("49" in r.text and "7*7" not in r.text
                                                and str(49) in r.text.replace("{{7*7}}", "")))
    if not hit:
        ok("no template evaluation")
        return
    u2, _ = inject(param, "{{7*8}}")
    try:
        r2 = get(u2)
        if "56" in r2.text:
            emit("ssti", "High", f"SSTI confirmed (7*7=49, 7*8=56) in '{param}'", pl, "Sandbox templates")
            return
    except requests.RequestException:
        pass
    ok("49-like content not confirmed as evaluation (possible FP)")

@module("idor", "IDOR probe (id swap)")
def m_idor():
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(URL).query, keep_blank_values=True)
    param = None
    for k in ["id", "user_id", "uid", "account", "order", "doc"]:
        if k in qs:
            param = k
            break
    if not param:
        skip("no id-ish param (use --param to force)")
        return
    u1, _ = inject(param, "1")
    u2, _ = inject(param, "2")
    try:
        r1 = get(u1, allow_redirects=False)
        r2 = get(u2, allow_redirects=False)
    except requests.RequestException as e:
        err(f"idor: {e}")
        return
    if (r1.status_code == r2.status_code == 200 and r1.text != r2.text
            and abs(len(r1.content) - len(r2.content)) > 30):
        emit("idor", "Medium", f"Sequential ID '{param}' returns different objects",
             f"len {len(r1.content)} vs {len(r2.content)}", "Object-level authz checks")
    else:
        ok(f"'{param}' swap shows no clear object difference (manual follow-up if auth'd)")

@module("xxe", "XML external entity (POST)")
def m_xxe():
    payload = ('<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
               "<f>&x;</f>")
    try:
        r = post(URL, data=payload, headers={"Content-Type": "application/xml"})
    except requests.RequestException as e:
        err(f"xxe: {e}")
        return
    if "root:x:0:0" in r.text or "root:*:0:0" in r.text:
        emit("xxe", "High", "XXE: /etc/passwd disclosed", "", "Disable external entities")
    elif "<!DOCTYPE" not in r.text and r.status_code in (400, 415, 406):
        skip("endpoint rejects XML")
    else:
        ok("no entity expansion observed")

@module("crlf", "CRLF injection")
def m_crlf():
    marker = "tbhcrlf"
    u, param = inject(None, f"%0d%0aSet-Cookie: {marker}=1")
    try:
        r = get(u, allow_redirects=False)
    except requests.RequestException as e:
        err(f"crlf: {e}")
        return
    sc = r.headers.get("Set-Cookie", "")
    hdr_names = [n for n, _ in r.raw.headers.items()] if hasattr(r.raw, "headers") else []
    if marker in sc or any(marker in str(v) for v in r.headers.values()):
        emit("crlf", "High", f"CRLF in '{param}' sets arbitrary header", sc[:80], "Encode CR/LF")
    else:
        ok("no header injection")

@module("clickjack", "Clickjacking (framing)")
def m_clickjack():
    try:
        r = get(URL)
    except requests.RequestException as e:
        err(f"clickjack: {e}")
        return
    xfo = r.headers.get("X-Frame-Options", "")
    csp = r.headers.get("Content-Security-Policy", "")
    if not xfo and "frame-ancestors" not in csp:
        emit("clickjack", "Low", "No framing protection", "no XFO/CSP frame-ancestors",
             "Add X-Frame-Options or CSP frame-ancestors")
    else:
        ok(f"framing protected ({xfo or 'CSP frame-ancestors'})")

@module("4xx", "4xx access-control bypass")
def m_4xx():
    base = URL.rstrip("/")
    admin = f"{base}/admin"
    try:
        r = get(admin, allow_redirects=False)
    except requests.RequestException as e:
        err(f"4xx: {e}")
        return
    if r.status_code not in (401, 403, 404):
        skip(f"/admin returned {r.status_code} (not access-controlled)")
        return
    for hdr in [{"X-Original-URL": "/admin"}, {"X-Rewrite-URL": "/admin"},
                {"X-Forwarded-For": "127.0.0.1"}]:
        try:
            r2 = get(admin, headers=hdr, allow_redirects=False)
        except requests.RequestException:
            continue
        if r2.status_code == 200 and len(r2.content) != len(r.content):
            emit("4xx", "High", f"Access-control bypass via {list(hdr)[0]}", f"{r.status_code} -> 200",
                 "Remove gateway-only header handling")
            return
    ok("no bypass with common header tricks")

@module("proto", "Prototype pollution (reflection)")
def m_proto():
    payload = '{"__proto__":{"tbhPolluted":"yes"},"constructor":{"prototype":{"tbhPolluted":"yes"}}}'
    try:
        r = post(URL, data=payload, headers={"Content-Type": "application/json"})
    except requests.RequestException as e:
        err(f"proto: {e}")
        return
    if "tbhpolluted" in r.text.lower():
        emit("proto", "High", "JSON body reflected into JS context", "", "Reject __proto__ keys")
    else:
        ok("no obvious reflection (client-side check still manual)")

@module("cache", "Web cache deception")
def m_cache():
    try:
        r = get(URL, headers={"Cache-Control": "no-cache"}, allow_redirects=False)
        r2 = get(URL.rstrip("/") + "/app.css", allow_redirects=False)
    except requests.RequestException as e:
        err(f"cache: {e}")
        return
    cache_hdr = r2.headers.get("X-Cache", "") + r2.headers.get("CF-Cache-Status", "")
    if r2.status_code == 200 and cache_hdr and "HIT" in cache_hdr.upper():
        emit("cache", "Medium", "Static-path variant served from cache", cache_hdr, "Fix cache keying")
    else:
        ok("no cache hit on deceptive path")

@module("jwt", "JWT detection & inspection")
def m_jwt():
    try:
        r = get(URL)
    except requests.RequestException as e:
        err(f"jwt: {e}")
        return
    m = re.search(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", r.text)
    if not m and "eyJ" in (S.cookies.get("token") or ""):
        m = re.match(r"(eyJ[\w\-]+\.[\w\-]+\.[\w\-]*)", S.cookies.get("token"))
    token = m.group(0) if m else (S.cookies.get("token") or "")
    if not token or not token.startswith("eyJ"):
        ok("no JWT found in body/cookies")
        return
    try:
        h = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
        p = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    except (ValueError, IndexError):
        err("JWT found but not decodable")
        return
    emit("jwt", "Info", f"JWT alg={h.get('alg')} typ={h.get('typ', '')}",
         f"exp={p.get('exp', 'none')}", "Verify signing")
    if h.get("alg", "").lower() == "none":
        emit("jwt", "High", "JWT algorithm 'none'", token[:40] + "...", "Reject alg=none server-side")
    if isinstance(p.get("exp"), int) and p["exp"] < time.time():
        emit("jwt", "Low", "JWT expired", datetime.fromtimestamp(p["exp"], timezone.utc).isoformat(),
             "Handle expiry")

@module("csrf", "CSRF token presence heuristic")
def m_csrf():
    try:
        r = get(URL)
    except requests.RequestException as e:
        err(f"csrf: {e}")
        return
    if r.status_code == 200 and re.search(r"<form", r.text, re.I):
        has_token = bool(re.search(r"csrf|_token|authenticity_token|xsrf", r.text, re.I))
        has_cookie = any(re.search(r"csrf|xsrf", k, re.I) for k in S.cookies.keys())
        if has_cookie and not has_token:
            emit("csrf", "Medium", "CSRF cookie without form token", "", "Add synchronizer token")
        elif not has_token:
            emit("csrf", "Low", "Form without visible CSRF token", "", "Confirm double-submit design")
        else:
            ok("CSRF token present in form")
    else:
        skip("no HTML form on this URL")

@module("cmdi", "OS command injection (error/time-safe)")
def m_cmdi():
    b = baseline_for(URL)
    hit, param, pl = probe_inject(None, [";id", "|id", "`id`"],
                                  lambda r, p: ("uid=0" in r.text or "uid=1000" in r.text
                                                or re.search(r"uid=\d+\(\w+\)", r.text)) and len(r.text) != b.get("len", -1))
    if hit:
        emit("cmdi", "High", f"Command output in '{param}'", pl, "Avoid shell / allowlist input")
    else:
        ok("no command output reflection")

@module("backup", "Backup file disclosure")
def m_backup():
    base = URL.rstrip("/")
    for path in ["backup.zip", "db.sql", "site.tar.gz", "www.zip"]:
        try:
            r = get(f"{base}/{path}", allow_redirects=False, stream=True)
        except requests.RequestException:
            continue
        if r.status_code == 200:
            ct = r.headers.get("Content-Type", "")
            if "html" not in ct:
                emit("backup", "High", f"Backup accessible: /{path}", ct, "Remove from webroot")
                r.close()
                return
        r.close()
    ok("no backup files in common paths")

@module("info", "Information disclosure")
def m_info():
    try:
        r = get(URL)
    except requests.RequestException as e:
        err(f"info: {e}")
        return
    if r.headers.get("X-Powered-By"):
        emit("info", "Info", "X-Powered-By disclosed", r.headers["X-Powered-By"], "Suppress header")
    if re.search(r"phpinfo\(\)|PHP Version", r.text):
        emit("info", "High", "phpinfo() exposed", "", "Remove in production")
    if not r.headers.get("X-Powered-By") and "phpinfo" not in r.text.lower():
        ok("no obvious disclosure")

@module("takeover", "Subdomain takeover (NXDOMAIN + CNAME)")
def m_takeover():
    import struct
    def dns_query(name, qtype=5):
        tid = b"\x13\x37"
        flags = b"\x01\x00"
        counts = struct.pack(">HHHH", 1, 0, 0, 0)
        q = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\x00"
        q += struct.pack(">HH", qtype, 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(tid + flags + counts + q, ("8.8.8.8", 53))
            data, _ = sock.recvfrom(512)
        except OSError:
            return None
        finally:
            sock.close()
        if len(data) < 12 or data[3] & 0x0F != 0:
            return None
        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount == 0:
            return None
        i = 12
        while data[i] != 0:
            i += 1 + data[i]
        i += 5
        if i + 12 > len(data) or data[i] & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", data[i:i + 2])[0] & 0x3FFF
            j = ptr
            labels = []
            while data[j] != 0 and data[j] & 0xC0 == 0:
                ln = data[j]
                labels.append(data[j + 1:j + 1 + ln].decode())
                j += 1 + ln
            return ".".join(labels)
        return None
    for sub in ["www", "app", "shop", "blog", "shopify", "s3"]:
        host = f"{sub}.{DOMAIN}"
        try:
            socket.gethostbyname(host)
            cname = dns_query(host)
            if cname:
                providers = ("github.io", "herokuapp.com", "amazonaws.com", "azurewebsites.net",
                             "shopify.com", "fastly.net", "ghost.io", "surge.sh")
                sev = "Medium" if any(p in cname for p in providers) else "Info"
                emit("takeover", sev, f"CNAME {host} -> {cname}",
                     "known provider" if sev == "Medium" else "", "Confirm dangling zone")
        except socket.gaierror:
            emit("takeover", "Info", f"NXDOMAIN {host}", "dangling only if referenced in JS/DNS records",
                 "Check JS sources & CNAME records")

@module("graphql", "GraphQL endpoint + introspection")
def m_graphql():
    base = URL.rstrip("/")
    for path in ["/graphql", "/graphiql", "/api/graphql"]:
        try:
            r = get(base + path, allow_redirects=False)
        except requests.RequestException:
            continue
        if r.status_code in (200, 400) and ("graphql" in r.text.lower() or r.status_code == 400):
            emit("graphql", "Info", f"GraphQL endpoint: {path}", f"HTTP {r.status_code}",
                 "Confirm introspection")
            try:
                r2 = post(base + path, json={"query": "{__typename}"})
                if r2.status_code == 200 and "data" in r2.text:
                    emit("graphql", "Medium", "Introspection enabled", "", "Disable in production")
            except requests.RequestException:
                pass
            return
    ok("no GraphQL endpoint in common paths")

@module("methods", "Dangerous HTTP methods")
def m_methods():
    try:
        r = get(URL, headers={"Origin": ""}, allow_redirects=False)
        opts = requests.options if hasattr(requests, "options") else None
        r2 = S.options(URL, timeout=ARGS.timeout)
    except requests.RequestException as e:
        err(f"methods: {e}")
        return
    allow = r2.headers.get("Allow", r.headers.get("Allow", ""))
    dangerous = [m for m in ["PUT", "DELETE", "TRACE", "PATCH"] if m in allow.upper()]
    if dangerous:
        sev = "Medium" if "TRACE" in dangerous or "DELETE" in dangerous else "Low"
        emit("methods", sev, f"Allow: {allow}", "", "Disable unused methods")
    else:
        ok(f"Allow: {allow or 'not disclosed'}")

@module("session", "Session cookie flags")
def m_session():
    try:
        get(URL)
    except requests.RequestException as e:
        err(f"session: {e}")
        return
    if not S.cookies:
        skip("no cookies set")
        return
    for k in S.cookies:
        cook = "; ".join(f"{c.name}={c.value}" for c in S.cookies)
        if not S.cookies[k].secure and URL.startswith("https"):
            emit("session", "Medium", f"Cookie '{k}' missing Secure", "", "Set Secure flag")
        break
    raw = str(S.cookies)
    if "_HttpOnly" not in str([getattr(x, "rest", {}) for x in S.cookies]) and "httponly" not in raw.lower():
        emit("session", "Low", "Cookie without HttpOnly", raw[:60], "Set HttpOnly flag")
    if not any(s in raw.lower() for s in ["samesite"]):
        emit("session", "Info", "No SameSite attribute observed", "", "Set SameSite=Lax/Strict")

@module("sensitive", "Secrets / sensitive data in source")
def m_sensitive():
    try:
        r = get(URL)
    except requests.RequestException as e:
        err(f"sensitive: {e}")
        return
    pats = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Google API key": r"AIza[0-9A-Za-z_\-]{35}",
        "Generic secret": r"(?i)(api[_-]?key|secret|password)\s*[=:]\s*['\"][^'\"]{8,}",
        "Email address": r"[\w.+-]+@[\w-]+\.[\w.]{2,}",
        "Bearer token": r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}",
    }
    hits = 0
    for name, pat in pats.items():
        m = re.search(pat, r.text)
        if m:
            hits += 1
            emit("sensitive", "High" if "key" in name.lower() or "secret" in name.lower() else "Info",
                 f"{name} in HTML", m.group(0)[:40] + "...", "Remove from source")
    if not hits:
        ok("no secrets in source")

@module("upload", "File upload form discovery")
def m_upload():
    try:
        r = get(URL)
    except requests.RequestException as e:
        err(f"upload: {e}")
        return
    if re.search(r'type=["\']file["\']', r.text, re.I):
        emit("upload", "Info", "File input found on page", "", "Test extension/MIME bypass")
    else:
        ok("no file upload form here")

@module("websocket", "WebSocket endpoint discovery")
def m_ws():
    try:
        r = get(URL)
    except requests.RequestException as e:
        err(f"ws: {e}")
        return
    found = set(re.findall(r"wss?://[\w.\-/]+", r.text))
    for f in sorted(found):
        emit("websocket", "Info", "WS endpoint in source", f, "Check auth on messages")
    if not found:
        ok("no ws:// endpoints in source")

@module("ldap", "LDAP injection (error-based)")
def m_ldap():
    b = baseline_for(URL)
    markers = ["ldap_", "invalid dn syntax", "ldap search failed", "unterminated"]
    hit, param, pl = probe_inject(None, ["*", "*)(&", "admin)(&"],
                                  lambda r, p: any(mk in r.text.lower() for mk in markers)
                                  and "ldap" in r.text.lower())
    if hit:
        emit("ldap", "High", f"LDAP error in '{param}'", pl, "Escape LDAP metacharacters")
    else:
        ok("no LDAP error leakage")

@module("xpath", "XPath injection (error-based)")
def m_xpath():
    markers = ["xpathexception", "xml parser", "xpath error", "invalid expression"]
    hit, param, pl = probe_inject(None, ["'", "\"'", "' or '1'='1"],
                                  lambda r, p: any(mk in r.text.lower() for mk in markers))
    if hit:
        emit("xpath", "High", f"XPath error in '{param}'", pl, "Use parametrized XPath")
    else:
        ok("no XPath error leakage")

@module("hpp", "HTTP parameter pollution")
def m_hpp():
    param = first_param()
    if not param:
        skip("no params in URL (use --param)")
        return
    u1, _ = inject(param, "1")
    p = urllib.parse.urlparse(u1)
    qs = urllib.parse.parse_qs(p.query)
    qs[param] = ["1", "2"]
    u2 = urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(qs, doseq=True)))
    try:
        r1 = get(u1, allow_redirects=False)
        r2 = get(u2, allow_redirects=False)
    except requests.RequestException as e:
        err(f"hpp: {e}")
        return
    d = abs(len(r1.content) - len(r2.content))
    if r1.status_code == r2.status_code and d > max(50, int(0.05 * max(len(r1.content), 1))):
        emit("hpp", "Medium", f"Duplicate '{param}' changes response", f"delta {d} bytes",
             "Normalize params server-side")
    else:
        ok("no HPP behavior observed")

def run_module(name):
    print(c("93", f"[{name}] {MODULES[name]['desc']}"))
    try:
        MODULES[name]["fn"]()
    except requests.RequestException as e:
        err(f"request failed: {e}")
    except Exception as e:
        err(f"{type(e).__name__}: {e}")

def summary():
    print("=" * 60)
    weights = {"High": 25, "Medium": 10, "Low": 3, "Info": 1}
    score = min(100, sum(weights[f["severity"]] for f in FINDINGS))
    level = "Critical" if score >= 50 else "High" if score >= 30 else "Medium" if score >= 15 else "Low" if score else "None"
    sev_count = {s: sum(1 for f in FINDINGS if f["severity"] == s) for s in ["High", "Medium", "Low", "Info"]}
    print(c("96", f"[✓] {len(FINDINGS)} findings | {sev_count} | risk {level} ({score})"))
    return score, level

def setup(url, n_modules=None):
    global S, URL, DOMAIN, IP, BASE, BASELINE, FINDINGS
    URL = url if "://" in url else "https://" + url
    DOMAIN = urllib.parse.urlparse(URL).hostname or urllib.parse.urlparse(URL).netloc
    try:
        IP = socket.gethostbyname(DOMAIN)
    except socket.gaierror:
        return False
    S = build_session()
    FINDINGS.clear()
    BASELINE.clear()
    BASE = URL.rstrip("/")
    print(c("96", f"[*] {DOMAIN} ({IP}) - {n_modules or len(MODULES)} of {len(MODULES)} modules"))
    return True

def read_targets(path):
    targets = []
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    except OSError as e:
        print(c("91", f"[!] cannot read targets file: {e}"), file=sys.stderr)
    return targets

def scan_target(url, names):
    if not setup(url, len(names)):
        print(c("91", f"[!] cannot resolve {urllib.parse.urlparse(url if '://' in url else 'https://' + url).hostname}, skipped"), file=sys.stderr)
        return None
    start = time.time()
    for n in names:
        run_module(n)
    score, level = summary()
    return {"target": DOMAIN, "ip": IP, "url": URL, "elapsed": round(time.time() - start, 1),
            "risk_score": score, "risk_level": level,
            "findings": [dict(f, target=DOMAIN) for f in FINDINGS]}

def interactive():
    print(banner())
    print(c("96", "TBH-CLI v3 - real modules only, no simulated results"))
    print(" 1. Scan ALL modules")
    print(" 2. Quick scan (headers + ports + sensitive)")
    print(" 3. Multi-target scan (file with one URL per line)")
    print(" 4. List modules")
    print(" 5. Help")
    print(" 0. Exit")
    while True:
        ch = input(c("97", "\nPilih [1/2/3/4/5/0]: ")).strip()
        if ch in ("1", "2"):
            url = input(c("96", "URL: ")).strip()
            if not url:
                continue
            names = list(MODULES) if ch == "1" else ["headers", "ports", "sensitive"]
            res = scan_target(url, names)
            if res and input("Save JSON? (y/n): ").strip().lower() == "y":
                with open("report.json", "w") as fh:
                    json.dump({"tool": "TBH-CLI", "version": VERSION, **res}, fh, indent=2)
                print("[✓] report.json")
        elif ch == "3":
            path = input(c("96", "targets file: ")).strip()
            targets = read_targets(path)
            if not targets:
                print("[!] no targets read")
                continue
            results = [r for t in targets if (r := scan_target(t, list(MODULES)))]
            print(c("96", f"[*] {len(results)}/{len(targets)} targets scanned"))
            if results and input("Save JSON? (y/n): ").strip().lower() == "y":
                with open("report.json", "w") as fh:
                    json.dump({"tool": "TBH-CLI", "version": VERSION,
                               "summary": {"targets": len(results),
                                           "findings": sum(len(r["findings"]) for r in results)},
                               "targets": results}, fh, indent=2)
                print("[✓] report.json")
        elif ch == "4":
            for i, (n, m) in enumerate(MODULES.items(), 1):
                print(f"  {i:2}. {n:12} {m['desc']}")
        elif ch == "5":
            print("Command: python3 tbh -u https://example.com -m xss,sqli --json r.json")
            print("Multi:   python3 tbh --targets scope.txt --json r.json")
            print("Modules: python3 tbh --list | Proxy: HTTPS_PROXY=http://127.0.0.1:8080 python3 tbh ...")
        elif ch == "0":
            print("Bye - Always Smile :)")
            break

def esc(t):
    import html
    return html.escape(str(t))

def write_html(data, path):
    rows = []
    sev_count = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    if "targets" in data:
        for t in data["targets"]:
            for f in t["findings"]:
                sev_count[f["severity"]] += 1
                rows.append(f"<tr><td><span class='sev {f['severity'].lower()}'>{f['severity']}</span></td>"
                            f"<td>{esc(t['target'])}</td><td>{esc(f['module'])}</td>"
                            f"<td>{esc(f['title'])}</td><td>{esc(f['detail'])}</td><td>{esc(f['fix'])}</td></tr>")
        summary = data.get("summary", {})
        target_line = f"{summary.get('targets', len(data['targets']))} targets"
        risk = "see per-target reports"
    else:
        for f in data.get("findings", []):
            sev_count[f["severity"]] += 1
            rows.append(f"<tr><td><span class='sev {f['severity'].lower()}'>{f['severity']}</span></td>"
                        f"<td>{esc(data.get('target', ''))}</td><td>{esc(f['module'])}</td>"
                        f"<td>{esc(f['title'])}</td><td>{esc(f['detail'])}</td><td>{esc(f['fix'])}</td></tr>")
        target_line = esc(data.get("target", ""))
        risk = f"{esc(data.get('risk_level', ''))} ({data.get('risk_score', '')})"
    total = sum(sev_count.values())
    cards = "".join(f"<div class='card'><b>{sev_count[s]}</b><span>{s}</span></div>"
                    for s in ["High", "Medium", "Low", "Info"])
    table = ("\n".join(rows) if rows else
             "<tr><td colspan='6' class='none'>No findings</td></tr>")
    doc = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>TBH-CLI Report</title>
<style>
body{{background:#0d1117;color:#c9d1d9;font-family:ui-monospace,monospace;padding:24px}}
h1{{color:#ff7b72}} a{{color:#58a6ff}}
.cards{{display:flex;gap:12px;margin:16px 0}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 20px;text-align:center}}
.card b{{display:block;font-size:28px}} .card span{{color:#8b949e;font-size:12px}}
.sev{{padding:2px 8px;border-radius:10px;font-size:12px;font-weight:bold}}
.sev.high{{background:#da3633;color:#fff}} .sev.medium{{background:#d29922;color:#000}}
.sev.low{{background:#30363d;color:#c9d1d9}} .sev.info{{background:#1f6feb;color:#fff}}
table{{border-collapse:collapse;width:100%;margin-top:12px}}
td,th{{border:1px solid #30363d;padding:6px 8px;text-align:left;vertical-align:top;font-size:13px}}
th{{background:#161b22;color:#8b949e}} .none{{color:#8b949e;text-align:center}}
footer{{margin-top:18px;color:#8b949e;font-size:12px}}
</style></head><body>
<h1>TBH-CLI v{VERSION} Report</h1>
<p>Targets: <b>{target_line}</b> | Risk: <b>{risk}</b> | {total} findings</p>
<div class="cards">{cards}</div>
<table><tr><th>Severity</th><th>Target</th><th>Module</th><th>Finding</th><th>Detail</th><th>Fix</th></tr>
{table}</table>
<footer>Generated by TBH-CLI v{VERSION} - Tulungagung Black Hat. Authorized testing only.</footer>
</body></html>"""
    with open(path, "w") as fh:
        fh.write(doc)

def main():
    global ARGS, USE_COLOR
    parser = argparse.ArgumentParser(description=f"TBH-CLI v{VERSION} - {len(MODULES)} real modules")
    parser.add_argument("-u", "--url", help="target URL")
    parser.add_argument("--targets", help="file with one URL per line (multi-target)")
    parser.add_argument("-m", "--modules", help="comma list, e.g. xss,sqli")
    parser.add_argument("--list", action="store_true", help="list modules")
    parser.add_argument("--param", help="force injection parameter")
    parser.add_argument("--proxy", help="e.g. http://127.0.0.1:8080")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("-H", "--header", action="append", help="extra header, repeatable")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--json", help="save JSON findings")
    parser.add_argument("--html", help="save HTML report")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"TBH-CLI {VERSION}")
    ARGS = parser.parse_args()
    USE_COLOR = not ARGS.no_color and not os.environ.get("NO_COLOR")

    if ARGS.list:
        for n, m in MODULES.items():
            print(f"{n:12} {m['desc']}")
        return 0

    if not ARGS.url and not ARGS.targets:
        if len(sys.argv) == 1:
            interactive()
            return 0
        parser.error("-u or --targets is required")
        return 2

    if ARGS.modules:
        names = [n.strip().lower() for n in ARGS.modules.split(",") if n.strip()]
        unknown = [n for n in names if n not in MODULES]
        if unknown:
            print(c("91", f"[!] unknown modules: {', '.join(unknown)} (use --list)"), file=sys.stderr)
            return 2
    else:
        names = list(MODULES)

    print(banner())
    print(c("91", "[!] Authorized targets only."))
    targets = ([ARGS.url] if ARGS.url else []) + (read_targets(ARGS.targets) if ARGS.targets else [])
    if not targets:
        print(c("91", "[!] no targets to scan"), file=sys.stderr)
        return 2

    results = [r for t in targets if (r := scan_target(t, names))]

    if ARGS.json or ARGS.html:
        if len(results) == 1:
            data = {"tool": "TBH-CLI", "version": VERSION, **results[0]}
        else:
            data = {"tool": "TBH-CLI", "version": VERSION,
                    "summary": {"targets": len(results),
                                "findings": sum(len(r["findings"]) for r in results)},
                    "targets": results}
    if ARGS.json:
        try:
            with open(ARGS.json, "w") as fh:
                json.dump(data, fh, indent=2)
            print(f"[✓] JSON: {ARGS.json}")
        except OSError as e:
            print(c("91", f"[!] cannot write JSON: {e}"), file=sys.stderr)
            return 2
    if ARGS.html:
        try:
            write_html(data, ARGS.html)
            print(f"[✓] HTML: {ARGS.html}")
        except OSError as e:
            print(c("91", f"[!] cannot write HTML: {e}"), file=sys.stderr)
            return 2

    if not results:
        return 2
    worst = [f for r in results for f in r["findings"] if f["severity"] in ("High", "Medium")]
    return 1 if worst else 0

if __name__ == "__main__":
    sys.exit(main())
