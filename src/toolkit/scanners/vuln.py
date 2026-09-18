"""Authorized active detectors with SAFE payloads only (lab scope).

Consolidates TBH-XSS/SQLi/LFI/SSRF/CORS/OpenRedirect/SSTI/IDOR/DirFinder/JSLeak.
Every probe uses non-destructive evidence-only payloads, timeout, and
requires the caller to have passed safety.validate_target first.
"""
from __future__ import annotations

import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

import requests

from ..core.http import build_session
from ..core.models import Finding, ScanResult

SAFE_UA = "TBH-Toolkit/1.0 (+authorized-lab-use)"

SQLI_ERRORS = ["sql syntax", "mysql", "unclosed quotation", "ora-", "postgresql", "sqlite", "odbc", "jdbc"]


def _with_param(url: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(url if url.startswith("http") else "http://" + url)
    qs = urllib.parse.parse_qs(parsed.query)
    if not qs:
        sep = "&" if parsed.query else "?"
        return urllib.parse.urlunparse(parsed._replace(query=(parsed.query + sep + f"q={urllib.parse.quote(payload)}" if parsed.query else f"q={urllib.parse.quote(payload)}")))
    k = list(qs.keys())[0]
    qs[k] = payload
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))


def check_xss(url: str, session: requests.Session, timeout: float) -> Finding:
    payload = "<svg/onload=alert(1)>"
    test = _with_param(url, payload)
    try:
        r = session.get(test, timeout=timeout)
        reflected = payload in r.text or urllib.parse.quote(payload) in r.text
        return Finding(id="xss-reflected", title="Reflected XSS (evidence-only probe)",
            severity="HIGH" if reflected else "INFO", endpoint=test,
            evidence=f"HTTP {r.status_code}; reflected={reflected}",
            explanation="Safe benign string was reflected; real exploitability needs manual confirmation with encoding/context analysis.",
            remediation="Context-output-encode, use CSP, validate input on allowlist.",
            references=["https://owasp.org/www-community/attacks/xss/"], module="vuln.xss")
    except requests.RequestException as e:
        return Finding(id="xss-error", title="XSS probe failed", severity="INFO", endpoint=test,
            evidence=str(e)[:200], explanation="Network error.", remediation="Retry.", module="vuln.xss")


def check_sqli(url: str, session: requests.Session, timeout: float) -> Finding:
    evidences = []
    for payload in ["'", '"']:
        test = _with_param(url, payload)
        try:
            r = session.get(test, timeout=timeout)
            low = r.text.lower()
            if any(ind in low for ind in SQLI_ERRORS):
                return Finding(id="sqli-error", title="Possible SQL injection (DB error disclosed)",
                    severity="HIGH", endpoint=test, evidence=f"HTTP {r.status_code}; matched DB error string",
                    explanation="Database error text is reflected; indicates unsanitized SQL concatenation.",
                    remediation="Use parameterized queries / ORM bindings; hide DB errors; WAF is not a fix.",
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"], module="vuln.sqli")
            evidences.append(f"{payload}->{r.status_code}")
        except requests.RequestException as e:
            evidences.append(f"error:{e!s}"[:80])
    return Finding(id="sqli-not-detected", title="No SQL error-based signal", severity="INFO",
        endpoint=url, evidence="; ".join(evidences)[:300],
        explanation="Safe quote probes did not trigger DB errors.", remediation="No action; consider authenticated review.",
        module="vuln.sqli")


def check_lfi(url: str, session: requests.Session, timeout: float) -> Finding:
    payload = "../../../../etc/passwd"
    test = _with_param(url, payload)
    try:
        r = session.get(test, timeout=timeout)
        vuln = "root:" in r.text and "nobody" in r.text
        return Finding(id="lfi", title="Local File Inclusion probe",
            severity="HIGH" if vuln else "INFO", endpoint=test,
            evidence=f"HTTP {r.status_code}; passwd-pattern={vuln}",
            explanation="Benign traversal probe; only flags when /etc/passwd markers appear.",
            remediation="Allowlist file names; chroot/jail; reject path separators.",
            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/"],
            module="vuln.lfi")
    except requests.RequestException as e:
        return Finding(id="lfi-error", title="LFI probe failed", severity="INFO", endpoint=test,
            evidence=str(e)[:200], explanation="Network error.", remediation="Retry.", module="vuln.lfi")


def check_ssrf(url: str, session: requests.Session, timeout: float) -> Finding:
    # Evidence-only: use a reserved documentation URL, never real cloud metadata in auto mode.
    payload = "http://192.0.2.1.invalid/ssrf-probe"
    test = _with_param(url, payload)
    try:
        r = session.get(test, timeout=timeout)
        reflected = "192.0.2.1" in r.text or "ssrf-probe" in r.text
        return Finding(id="ssrf", title="SSRF probe (safe documentation URL)",
            severity="MEDIUM" if reflected else "INFO", endpoint=test,
            evidence=f"HTTP {r.status_code}; reflected={reflected}",
            explanation="Checks whether the URL parameter is fetched/reflected. Use Burp Collaborator manually for full PoC in your lab.",
            remediation="Allowlist outbound hosts; block cloud-metadata IPs; require auth for fetchers.",
            references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"], module="vuln.ssrf")
    except requests.RequestException as e:
        return Finding(id="ssrf-error", title="SSRF probe failed", severity="INFO", endpoint=test,
            evidence=str(e)[:200], explanation="Network error.", remediation="Retry.", module="vuln.ssrf")


def check_open_redirect(url: str, session: requests.Session, timeout: float) -> Finding:
    payload = "https://example.com/redirect-probe"
    parsed = urllib.parse.urlparse(url if url.startswith("http") else "http://" + url)
    qs = urllib.parse.parse_qs(parsed.query)
    if not qs:
        test = url.rstrip("/") + f"?redirect={urllib.parse.quote(payload)}"
    else:
        k = list(qs.keys())[0]
        qs[k] = payload
        test = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))
    try:
        r = session.get(test, timeout=timeout, allow_redirects=False)
        loc = r.headers.get("Location", "")
        vuln = "example.com" in loc
        return Finding(id="open-redirect", title="Open redirect probe",
            severity="MEDIUM" if vuln else "INFO", endpoint=test, evidence=f"HTTP {r.status_code}; Location={loc[:200]}",
            explanation="Benign example.com redirect target; flags only when server redirects to it.",
            remediation="Validate redirect targets against an allowlist; use relative URLs.",
            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect"],
            module="vuln.redirect")
    except requests.RequestException as e:
        return Finding(id="open-redirect-error", title="Open-redirect probe failed", severity="INFO",
            endpoint=test, evidence=str(e)[:200], explanation="Network error.", remediation="Retry.", module="vuln.redirect")


def check_ssti(url: str, session: requests.Session, timeout: float) -> Finding:
    payload = "{{7*7}}"
    test = _with_param(url, payload)
    try:
        r = session.get(test, timeout=timeout)
        # Weak heuristic kept from legacy, but require the payload context to avoid '49' false positives:
        vuln = payload not in r.text and re.search(r"(?<![0-9])49(?![0-9])", r.text) is not None and len(r.text) < 500_000
        # Safer: only flag when 49 appears AND payload echoed-evaluated pattern differs; keep INFO otherwise.
        return Finding(id="ssti", title="SSTI probe ({{7*7}})",
            severity="MEDIUM" if vuln else "INFO", endpoint=test,
            evidence=f"HTTP {r.status_code}; evaluated-49={bool(vuln)}",
            explanation="Safe math probe; '49' alone is weak evidence, confirm manually in lab.",
            remediation="Never render user input as template; use logic-less templates.",
            references=["https://owasp.org/www-community/attacks/Server_Side_Template_Injection"], module="vuln.ssti")
    except requests.RequestException as e:
        return Finding(id="ssti-error", title="SSTI probe failed", severity="INFO", endpoint=test,
            evidence=str(e)[:200], explanation="Network error.", remediation="Retry.", module="vuln.ssti")


def check_idor(url: str, session: requests.Session, timeout: float) -> list[Finding]:
    m = re.search(r"(\?|&)(id|user|account|profile)=(\d+)", url)
    out: list[Finding] = []
    if not m:
        out.append(Finding(id="idor-manual", title="IDOR: manual review needed (no numeric id param)",
            severity="INFO", endpoint=url, evidence="No ?id=<int> parameter found",
            explanation="Automated IDOR check needs an object reference; test with two lab accounts and compare.",
            remediation="Enforce per-object authorization server-side; use random UUIDs + authz checks.",
            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"],
            module="vuln.idor"))
        return out
    param, orig = m.group(2), m.group(3)
    for tid in [str(int(orig) + 1), "1"]:
        test = url.replace(f"{param}={orig}", f"{param}={tid}", 1)
        try:
            r = session.get(test, timeout=timeout)
            out.append(Finding(id=f"idor-{tid}", title=f"IDOR probe id={tid}",
                severity="INFO", endpoint=test, evidence=f"HTTP {r.status_code}; len={len(r.content)}",
                explanation="Compare responses between your own two lab accounts; differing data = confirm manually.",
                remediation="Authorization check on every object access.",
                references=["https://owasp.org/API-Security/editions/2023/en/0x11-t10/"], module="vuln.idor"))
        except requests.RequestException as e:
            out.append(Finding(id=f"idor-{tid}-error", title="IDOR probe failed", severity="INFO",
                endpoint=test, evidence=str(e)[:200], explanation="Network error.", remediation="Retry.", module="vuln.idor"))
    return out


COMMON_DIRS = ["admin", "login", "api", ".git", ".env", "robots.txt", "sitemap.xml", "swagger", "backup.zip"]


def check_dirs(base_url: str, session: requests.Session, timeout: float, threads: int = 5) -> list[Finding]:
    def probe(path: str) -> Finding | None:
        full = base_url.rstrip("/") + "/" + path
        try:
            r = session.get(full, timeout=timeout, allow_redirects=False)
            if r.status_code in (200, 301, 302, 401, 403):
                sev = "HIGH" if path in (".git", ".env") and r.status_code == 200 else ("MEDIUM" if r.status_code == 200 else "INFO")
                return Finding(id=f"dir-{path}", title=f"Sensitive path responds: /{path} [{r.status_code}]",
                    severity=sev, endpoint=full,  # type: ignore[arg-type]
                    evidence=f"HTTP {r.status_code}; {len(r.content)} bytes",
                    explanation="Exposed paths (esp. .git/.env) leak source or secrets.",
                    remediation="Remove from webroot; deny by default; audit deployments.",
                    module="vuln.dirs")
        except requests.RequestException:
            pass
        return None

    with ThreadPoolExecutor(max_workers=max(1, min(threads, 10))) as ex:
        results = list(ex.map(probe, COMMON_DIRS))
    return [r for r in results if r]


JS_SECRET_PATTERNS = {
    "aws-key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "api-key": re.compile(r"(?i)api[_-]?key\s*[:=]\s*['\"]([A-Za-z0-9_\-]{10,})['\"]"),
    "token": re.compile(r"(?i)token\s*[:=]\s*['\"]([A-Za-z0-9\-_.]{10,})['\"]"),
}


def check_js_leak(url: str, session: requests.Session, timeout: float) -> Finding:
    try:
        r = session.get(url, timeout=timeout)
        hits = {name: bool(p.search(r.text)) for name, p in JS_SECRET_PATTERNS.items()}
        js_links = re.findall(r'src=["\']([^"\']+\.js)', r.text)[:5]
        found = [k for k, v in hits.items() if v]
        return Finding(id="jsleak", title="JavaScript secret scan",
            severity="HIGH" if found else "INFO", endpoint=url,
            evidence=f"patterns={found or 'none'}; js={js_links or 'none'}",
            explanation="Regex scan of HTML for secret-like strings; verify in your own bundle only.",
            remediation="Never ship secrets in frontend; rotate any exposed key immediately.",
            module="vuln.jsleak")
    except requests.RequestException as e:
        return Finding(id="jsleak-error", title="JS scan failed", severity="INFO", endpoint=url,
            evidence=str(e)[:200], explanation="Network error.", remediation="Retry.", module="vuln.jsleak")


VULN_CHECKS = ["xss", "sqli", "lfi", "ssrf", "redirect", "ssti", "idor", "dirs", "jsleak", "cors"]


def scan_vuln(target: str, checks: list[str] | None = None, timeout: float = 8.0,
              user_agent: str = SAFE_UA, threads: int = 5) -> ScanResult:
    import datetime as _dt
    started = _dt.datetime.now(_dt.timezone.utc).isoformat()
    t0 = time.time()
    base = target if target.startswith(("http://", "https://")) else "http://" + target
    session = build_session(timeout=timeout, user_agent=user_agent)
    wanted = checks or ["xss", "sqli", "cors"]
    findings: list[Finding] = []
    if "xss" in wanted:
        findings.append(check_xss(base, session, timeout))
    if "sqli" in wanted:
        findings.append(check_sqli(base, session, timeout))
    if "lfi" in wanted:
        findings.append(check_lfi(base, session, timeout))
    if "ssrf" in wanted:
        findings.append(check_ssrf(base, session, timeout))
    if "redirect" in wanted:
        findings.append(check_open_redirect(base, session, timeout))
    if "ssti" in wanted:
        findings.append(check_ssti(base, session, timeout))
    if "idor" in wanted:
        findings += check_idor(base, session, timeout)
    if "dirs" in wanted:
        findings += check_dirs(base, session, timeout, threads)
    if "jsleak" in wanted:
        findings.append(check_js_leak(base, session, timeout))
    if "cors" in wanted:
        from .web import check_cors
        findings += check_cors(base, session, timeout)
    host = urllib.parse.urlparse(base).hostname or target
    return ScanResult(target=host, module="vuln", started_at=started,
                      duration_s=round(time.time() - t0, 2), findings=findings, meta={"url": base, "checks": wanted})
