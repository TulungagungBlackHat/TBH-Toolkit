"""Network diagnostics + opt-in rate-limited port scan (no exploitation)."""
from __future__ import annotations

import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from ..core.models import Finding, ScanResult
from ..core.safety import check_port_scan_limits

PORT_INFO = {21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
             143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
             6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"}


def tcp_check(host: str, port: int, timeout: float) -> tuple[bool, float, str]:
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        ok = s.connect_ex((host, port)) == 0
        banner = ""
        if ok:
            try:
                s.settimeout(1.0)
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(200).decode(errors="ignore").split("\n")[0][:120]
            except OSError:
                pass
        return ok, round((time.time() - t0) * 1000, 1), banner
    finally:
        s.close()


def scan_ports(host: str, ports: list[int], timeout: float = 1.5,
               threads: int = 10, rate_rps: float = 20.0) -> ScanResult:
    started = datetime.now(timezone.utc).isoformat()
    t0 = time.time()
    check_port_scan_limits(ports, threads, rate_rps)
    ip = socket.gethostbyname(host)
    gap = 1.0 / max(rate_rps, 0.1)
    findings: list[Finding] = []

    def probe(p: int) -> Finding:
        time.sleep(gap / max(threads, 1))
        ok, ms, banner = tcp_check(ip, p, timeout)
        return Finding(id=f"port-{p}", title=f"Port {p} {'OPEN' if ok else 'closed'} ({PORT_INFO.get(p, 'unknown')})",
            severity="INFO" if ok else "INFO", endpoint=f"{ip}:{p}",
            evidence=f"open={ok} rtt_ms={ms} banner={banner!r}",
            explanation="TCP connectivity only; no exploitation or credential attempts.",
            remediation="Close unused ports; firewall lab services.", module="network.ports",
            extra={"open": ok, "rtt_ms": ms, "port": p})

    with ThreadPoolExecutor(max_workers=threads) as ex:
        results = list(ex.map(probe, ports))
    findings += results
    opens = [f.extra["port"] for f in results if f.extra.get("open")]
    return ScanResult(target=host, module="network.ports", started_at=started,
                      duration_s=round(time.time() - t0, 2), findings=findings,
                      meta={"ip": ip, "open": opens, "scanned": len(ports)})


def diagnose(host: str, timeout: float = 3.0) -> ScanResult:
    started = datetime.now(timezone.utc).isoformat()
    t0 = time.time()
    findings: list[Finding] = []
    try:
        t = time.time()
        ip = socket.gethostbyname(host)
        findings.append(Finding(id="dns-ok", title=f"DNS resolves {host} -> {ip}",
            severity="INFO", endpoint=host, evidence=f"rtt_ms={round((time.time()-t)*1000,1)}",
            explanation="Local DNS resolution.", remediation="No action.", module="network.dns"))
    except OSError as e:
        findings.append(Finding(id="dns-fail", title="DNS resolution failed", severity="MEDIUM",
            endpoint=host, evidence=str(e)[:200], explanation="Cannot resolve target.",
            remediation="Check spelling, /etc/hosts, and lab DNS.", module="network.dns"))
        return ScanResult(target=host, module="network", started_at=started,
                          duration_s=round(time.time() - t0, 2), findings=findings)
    for port in (80, 443):
        ok, ms, banner = tcp_check(ip, port, timeout)
        findings.append(Finding(id=f"tcp-{port}", title=f"TCP {port} {'reachable' if ok else 'unreachable'}",
            severity="INFO", endpoint=f"{ip}:{port}", evidence=f"rtt_ms={ms} banner={banner!r}",
            explanation="Connectivity probe.", remediation="No action.", module="network.tcp"))
    return ScanResult(target=host, module="network", started_at=started,
                      duration_s=round(time.time() - t0, 2), findings=findings, meta={"ip": ip})
