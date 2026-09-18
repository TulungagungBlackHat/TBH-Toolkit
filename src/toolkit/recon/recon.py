"""Passive/authorized recon: DNS, HTTP meta, TLS cert, robots/security.txt.

Default is passive. --active enables only explicit, rate-limited,
lab-validated probes (no aggressive scanning by default).
"""
from __future__ import annotations

import socket
import time
from datetime import UTC, datetime
from urllib.parse import urlparse

import requests

from ..core.http import build_session
from ..core.models import Finding, ScanResult

PASSIVE_SUBS = ["www", "mail", "api", "blog", "shop", "dev", "test"]


def dns_info(domain: str, timeout: float = 3.0) -> dict:
    info: dict = {"domain": domain}
    try:
        info["ip"] = socket.gethostbyname(domain)
    except OSError as e:
        info["error"] = f"DNS failed: {e}"
        return info
    try:
        info["fqdn"] = socket.getfqdn(domain)
    except OSError:
        pass
    # reverse
    try:
        info["reverse"] = socket.gethostbyaddr(info["ip"])[0]
    except OSError:
        pass
    return info


def http_meta(url: str, timeout: float, user_agent: str) -> dict:
    s = build_session(timeout=timeout, user_agent=user_agent)
    try:
        r = s.get(url, timeout=timeout)
        return {"status": r.status_code, "server": r.headers.get("Server", "?"),
                "headers": dict(list(r.headers.items())[:30]), "length": len(r.content),
                "final_url": r.url}
    except requests.RequestException as e:
        return {"error": str(e)[:200]}


def passive_subdomains(domain: str) -> list[dict]:
    found = []
    for sub in PASSIVE_SUBS:
        host = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            found.append({"host": host, "ip": ip, "method": "passive-dns-resolve"})
        except OSError:
            continue
    return found


def scan_recon(target: str, timeout: float = 8.0, user_agent: str = "TBH-Toolkit/1.0",
               active: bool = False, include_subs: bool = False) -> ScanResult:
    started = datetime.now(UTC).isoformat()
    t0 = time.time()
    base = target if target.startswith(("http://", "https://")) else "http://" + target
    domain = urlparse(base).hostname or target
    findings: list[Finding] = []
    meta: dict = {}

    dns = dns_info(domain)
    meta["dns"] = dns
    findings.append(Finding(id="dns", title=f"DNS: {domain} -> {dns.get('ip', '?')}",
        severity="INFO", endpoint=domain, evidence=str(dns)[:400],
        explanation="Public DNS resolution.", remediation="No action.", module="recon.dns"))

    hm = http_meta(base, timeout, user_agent)
    meta["http"] = {k: v for k, v in hm.items() if k != "headers"}
    findings.append(Finding(id="http-meta", title=f"HTTP {hm.get('status', 'error')} {domain}",
        severity="INFO", endpoint=base, evidence=str({k: hm.get(k) for k in ('status', 'server', 'length')}),
        explanation="Non-invasive HTTP metadata.", remediation="No action.", module="recon.http"))

    if include_subs or active:
        subs = passive_subdomains(domain)
        meta["subdomains"] = subs
        for s in subs:
            findings.append(Finding(id=f"sub-{s['host']}", title=f"Subdomain resolves: {s['host']}",
                severity="INFO", endpoint=s["host"], evidence=str(s),
                explanation="Passive dictionary resolve against public DNS (lab-authorized).",
                remediation="No action; verify scope before deeper testing.", module="recon.subs"))

    if active:
        from ..scanners.web import check_wellknown as _cw
        s = build_session(timeout=timeout, user_agent=user_agent)
        findings += _cw(base, s, timeout)
    return ScanResult(target=domain, module="recon", started_at=started,
                      duration_s=round(time.time() - t0, 2), findings=findings, meta=meta)
