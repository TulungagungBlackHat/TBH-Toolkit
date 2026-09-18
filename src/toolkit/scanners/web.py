"""Defensive web security scanner: headers, TLS, cookies, CORS, disclosure.

Consolidates TBH-Recon / TBH-BugBounty / TBH-CLI header+SSL logic into one
finding-oriented module with severity + evidence + remediation + references.
"""
from __future__ import annotations

import re
import socket
import ssl
import time
from datetime import UTC, datetime
from urllib.parse import urljoin, urlparse

import requests

from ..core.http import build_session
from ..core.models import Finding, ScanResult

SEC_HEADERS = {
    "Strict-Transport-Security": ("MEDIUM", "HSTS missing: transport downgrade possible.",
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`."),
    "Content-Security-Policy": ("MEDIUM", "CSP missing: XSS impact is larger.",
        "Deploy a restrictive Content-Security-Policy and test in report-only mode first."),
    "X-Frame-Options": ("LOW", "Clickjacking protection header missing (or use frame-ancestors).",
        "Set `X-Frame-Options: DENY` or `frame-ancestors 'none'` in CSP."),
    "X-Content-Type-Options": ("LOW", "MIME-sniffing protection missing.",
        "Set `X-Content-Type-Options: nosniff`."),
    "Referrer-Policy": ("LOW", "Referrer leakage policy not set.",
        "Set `Referrer-Policy: strict-origin-when-cross-origin` or stricter."),
    "Permissions-Policy": ("INFO", "Feature permissions policy not set.",
        "Set `Permissions-Policy` to disable unused browser features."),
}
SERVER_DISCLOSURE = re.compile(r"(apache/\d|nginx/\d|php/\d|iis/\d|express|gunicorn|werkzeug|django|laravel)", re.IGNORECASE)
EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

REFS = {
    "headers": ["https://owasp.org/www-project-secure-headers/", "https://infosec.mozilla.org/guidelines/web_security"],
    "tls": ["https://wiki.mozilla.org/Security/Server_Side_TLS", "https://owasp.org/www-project-transport-layer-protection-cheat-sheet/"],
    "cookies": ["https://owasp.org/www-community/controls/SecureCookieAttribute", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"],
    "cors": ["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
}


def _norm_target(target: str) -> str:
    return target if target.startswith(("http://", "https://")) else "http://" + target


def check_security_headers(resp: requests.Response, endpoint: str) -> list[Finding]:
    findings: list[Finding] = []
    for header, (sev, expl, fix) in SEC_HEADERS.items():
        if header not in resp.headers:
            findings.append(Finding(
                id=f"missing-{header.lower()}", title=f"Missing security header: {header}",
                severity=sev, endpoint=endpoint,  # type: ignore[arg-type]
                evidence=f"Response headers: {sorted(resp.headers.keys())[:20]}",
                explanation=expl, remediation=fix, references=list(REFS["headers"]), module="web.headers",
            ))
    return findings


def check_cookies(resp: requests.Response, endpoint: str) -> list[Finding]:
    findings: list[Finding] = []
    raw = resp.headers.get("Set-Cookie", "")
    if not raw:
        return [Finding(id="cookies-none", title="No session cookies observed", severity="INFO",
                        endpoint=endpoint, evidence="No Set-Cookie header",
                        explanation="Nothing to audit for cookie flags.", remediation="No action.",
                        module="web.cookies")]
    low = raw.lower()
    if "secure" not in low:
        findings.append(Finding(id="cookie-no-secure", title="Cookie without Secure flag", severity="MEDIUM",
            endpoint=endpoint, evidence=raw[:300], explanation="Cookies may be sent over HTTP.",
            remediation="Set `Secure` on all session cookies.", references=list(REFS["cookies"]), module="web.cookies"))
    if "httponly" not in low:
        findings.append(Finding(id="cookie-no-httponly", title="Cookie without HttpOnly flag", severity="LOW",
            endpoint=endpoint, evidence=raw[:300], explanation="JS can read the cookie; XSS impact is larger.",
            remediation="Set `HttpOnly` on session cookies.", references=list(REFS["cookies"]), module="web.cookies"))
    if "samesite" not in low:
        findings.append(Finding(id="cookie-no-samesite", title="Cookie without SameSite attribute", severity="LOW",
            endpoint=endpoint, evidence=raw[:300], explanation="CSRF risk is higher without SameSite.",
            remediation="Set `SameSite=Lax` or `Strict`.", references=list(REFS["cookies"]), module="web.cookies"))
    return findings


def check_cors(base_url: str, session: requests.Session, timeout: float) -> list[Finding]:
    try:
        r = session.get(base_url, headers={"Origin": "https://evil.example"}, timeout=timeout)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "https://evil.example" or (acao == "*" and acac.lower() == "true"):
            return [Finding(id="cors-misconfig", title="CORS misconfiguration (arbitrary origin reflected)",
                severity="HIGH", endpoint=base_url, evidence=f"ACAO={acao!r} ACAC={acac!r}",
                explanation="Any site can read cross-origin responses; data theft possible.",
                remediation="Echo only allowlisted origins; never use `*` with credentials.",
                references=list(REFS["cors"]), module="web.cors")]
        if acao == "*":
            return [Finding(id="cors-wildcard", title="CORS wildcard origin", severity="LOW",
                endpoint=base_url, evidence=f"ACAO={acao!r}",
                explanation="Public resources may be intentionally wildcarded; sensitive APIs must not be.",
                remediation="Restrict ACAO to trusted origins for authenticated endpoints.",
                references=list(REFS["cors"]), module="web.cors")]
        return [Finding(id="cors-ok", title="CORS policy looks restrictive", severity="INFO",
            endpoint=base_url, evidence=f"ACAO={acao!r} ACAC={acac!r}",
            explanation="Arbitrary origin was not reflected.", remediation="No action.", module="web.cors")]
    except requests.RequestException as e:
        return [Finding(id="cors-error", title="CORS check failed (network error)", severity="INFO",
            endpoint=base_url, evidence=str(e)[:200], explanation="Could not complete CORS probe.",
            remediation="Retry; check connectivity.", module="web.cors")]


def check_tls(host: str, port: int = 443, timeout: float = 5.0) -> list[Finding]:
    findings: list[Finding] = []
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            cert = s.getpeercert()
            cipher = s.cipher()
            expire = str(cert.get("notAfter", ""))
            try:
                exp_dt = datetime.strptime(expire, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
                days = (exp_dt - datetime.now(UTC)).days
            except ValueError:
                days = 999
            if days < 0:
                findings.append(Finding(id="tls-expired", title="TLS certificate expired", severity="HIGH",
                    endpoint=f"https://{host}:{port}", evidence=f"notAfter={expire}",
                    explanation="Clients will refuse the connection.", remediation="Renew the certificate.",
                    references=list(REFS["tls"]), module="web.tls"))
            elif days < 30:
                findings.append(Finding(id="tls-expiring", title=f"TLS certificate expires in {days} days",
                    severity="MEDIUM", endpoint=f"https://{host}:{port}", evidence=f"notAfter={expire}",
                    explanation="Short-lived cert needs rotation soon.", remediation="Renew before expiry; automate renewal.",
                    references=list(REFS["tls"]), module="web.tls"))
            else:
                findings.append(Finding(id="tls-ok", title=f"TLS certificate valid ({days} days left)",
                    severity="INFO", endpoint=f"https://{host}:{port}",
                    evidence=f"notAfter={expire} cipher={cipher[0] if cipher else '?'}",
                    explanation="Certificate chain validated.", remediation="No action.", module="web.tls"))
    except (OSError, ValueError) as e:  # no TLS / connection refused
        findings.append(Finding(id="tls-unavailable", title="TLS inspection unavailable", severity="INFO",
            endpoint=f"https://{host}:{port}", evidence=str(e)[:200],
            explanation="Host may be HTTP-only or unreachable on 443.", remediation="Enable HTTPS if this is a web service.",
            module="web.tls"))
    return findings


def check_disclosure(resp: requests.Response, endpoint: str) -> list[Finding]:
    findings: list[Finding] = []
    server = resp.headers.get("Server", "") + " " + resp.headers.get("X-Powered-By", "")
    m = SERVER_DISCLOSURE.search(server)
    if m:
        findings.append(Finding(id="server-disclosure", title=f"Server version disclosed: {m.group(0)}",
            severity="LOW", endpoint=endpoint, evidence=f"Server={server.strip()[:200]}",
            explanation="Version banners help attackers fingerprint.", remediation="Minimize Server/X-Powered-By banners.",
            references=list(REFS["headers"]), module="web.disclosure"))
    emails = sorted(set(EMAIL_RE.findall(resp.text[:20000])))[:5]
    if emails:
        findings.append(Finding(id="email-disclosure", title="Email addresses exposed in HTML",
            severity="INFO", endpoint=endpoint, evidence=", ".join(emails),
            explanation="Harvestable for phishing.", remediation="Avoid publishing raw emails; use contact forms.",
            module="web.disclosure"))
    return findings


def check_wellknown(base_url: str, session: requests.Session, timeout: float) -> list[Finding]:
    findings: list[Finding] = []
    for path, fid, title in [
        ("/robots.txt", "robots", "robots.txt present"),
        ("/security.txt", "security-txt", "security.txt present"),
        ("/.well-known/security.txt", "security-txt-wellknown", "well-known security.txt present"),
        ("/sitemap.xml", "sitemap", "sitemap.xml present"),
    ]:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            r = session.get(url, timeout=timeout, allow_redirects=False)
            if r.status_code == 200 and len(r.content) < 200_000:
                sev = "INFO"
                if path == "/robots.txt" and re.search(r"(?i)disallow:\s*/(admin|backup|\.git|\.env)", r.text):
                    sev = "LOW"  # type: ignore[assignment]
                    title2 = "robots.txt exposes sensitive paths"
                    findings.append(Finding(id="robots-sensitive", title=title2, severity="LOW",
                        endpoint=url, evidence=r.text[:300], explanation="robots.txt hints at hidden paths.",
                        remediation="Ensure listed paths are access-controlled; robots.txt is not access control.",
                        module="web.wellknown"))
                    continue
                findings.append(Finding(id=fid, title=title, severity=sev,  # type: ignore[arg-type]
                    endpoint=url, evidence=f"HTTP {r.status_code}, {len(r.content)} bytes",
                    explanation="Standard discovery file.", remediation="Keep it accurate and minimal.", module="web.wellknown"))
            elif path in ("/security.txt", "/.well-known/security.txt") and r.status_code == 404:
                findings.append(Finding(id=fid + "-missing", title="security.txt missing", severity="INFO",
                    endpoint=url, evidence="HTTP 404",
                    explanation="No coordinated-disclosure contact advertised.",
                    remediation="Consider publishing /.well-known/security.txt (RFC 9116).", module="web.wellknown"))
        except requests.RequestException:
            pass
    return findings


def scan_web(target: str, timeout: float = 8.0, user_agent: str = "TBH-Toolkit/1.0",
             check_tls_flag: bool = True) -> ScanResult:
    started = datetime.now(UTC).isoformat()
    t0 = time.time()
    base = _norm_target(target)
    host = urlparse(base).hostname or target
    session = build_session(timeout=timeout, user_agent=user_agent)
    findings: list[Finding] = []
    try:
        resp = session.get(base, timeout=timeout)
        endpoint = resp.url
        findings.append(Finding(id="http-status", title=f"HTTP {resp.status_code} from {host}",
            severity="INFO", endpoint=endpoint, evidence=f"status={resp.status_code} server={resp.headers.get('Server','?')}",
            explanation="Baseline connectivity.", remediation="No action.", module="web.http"))
        findings += check_security_headers(resp, endpoint)
        findings += check_cookies(resp, endpoint)
        findings += check_disclosure(resp, endpoint)
    except requests.RequestException as e:
        findings.append(Finding(id="http-error", title="Could not fetch target", severity="MEDIUM",
            endpoint=base, evidence=str(e)[:300], explanation="Target unreachable or timed out.",
            remediation="Verify target, port, and lab network connectivity.", module="web.http"))
        return ScanResult(target=host, module="web", started_at=started,
                          duration_s=round(time.time() - t0, 2), findings=findings)
    findings += check_cors(base, session, timeout)
    findings += check_wellknown(base, session, timeout)
    if check_tls_flag and urlparse(base).scheme == "https":
        findings += check_tls(host)
    return ScanResult(target=host, module="web", started_at=started,
                      duration_s=round(time.time() - t0, 2), findings=findings,
                      meta={"url": base})
