"""Safety boundary: target allowlist, explicit confirmation, limits.

This is the core guardrail that converts legacy offensive tools
(DDoS, deface PUT, credential attack) into authorized-only equivalents.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

ALLOWLIST_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}
# RFC1918 + loopback + link-local + test nets are lab-safe by default.
SAFE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]
SAFE_SUFFIXES = (".local", ".localhost", ".lab", ".internal", ".test", ".example", ".invalid")
SAFE_DOMAINS = {"example.com", "example.org", "example.net", "test.local"}

MAX_REQUESTS = 2000
MAX_CONCURRENCY = 20
MIN_RATE_RPS = 0.1
MAX_RATE_RPS = 50.0


class SafetyError(ValueError):
    """Raised when a target fails the authorized-use policy."""


def hostname_from_target(target: str) -> str:
    t = target.strip()
    if "://" not in t:
        t = "http://" + t
    host = urlparse(t).hostname or t.split("/")[0].split(":")[0]
    return host.lower().strip().rstrip(".")


def is_lab_host(host: str) -> bool:
    h = host.lower().strip().rstrip(".")
    if h in ALLOWLIST_HOSTNAMES or h in SAFE_DOMAINS:
        return True
    if h.endswith(SAFE_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return any(ip in net for net in SAFE_NETWORKS)
    except ValueError:
        pass
    # Resolve DNS and check the resolved IP is lab-local.
    try:
        resolved = socket.gethostbyname(h)
        ip = ipaddress.ip_address(resolved)
        return any(ip in net for net in SAFE_NETWORKS)
    except (OSError, ValueError):
        return False


def validate_target(target: str, *, allow_external: bool = False, confirm_external: bool = False) -> str:
    """Return normalized hostname or raise SafetyError."""
    if not target or not target.strip():
        raise SafetyError("target is empty")
    host = hostname_from_target(target)
    if not host or len(host) > 253:
        raise SafetyError(f"invalid target: {target!r}")
    if is_lab_host(host):
        return host
    if allow_external and confirm_external:
        return host
    if allow_external and os.environ.get("TOOLKIT_I_OWN_THIS_TARGET") == "1":
        return host
    raise SafetyError(
        f"target {host!r} is not lab-local. Default policy allows only "
        "localhost / RFC1918 / .lab/.test / example.* domains. "
        "For an authorized external assessment re-run with --allow-external --confirm-external "
        "(you must own the target or have written permission), "
        "or set TOOLKIT_I_OWN_THIS_TARGET=1."
    )


def check_loadtest_limits(requests_n: int, concurrency: int, rate: float) -> None:
    if requests_n < 1 or requests_n > MAX_REQUESTS:
        raise SafetyError(f"--requests must be 1..{MAX_REQUESTS} (got {requests_n})")
    if concurrency < 1 or concurrency > MAX_CONCURRENCY:
        raise SafetyError(f"--concurrency must be 1..{MAX_CONCURRENCY} (got {concurrency})")
    if not (MIN_RATE_RPS <= rate <= MAX_RATE_RPS):
        raise SafetyError(f"--rate must be {MIN_RATE_RPS}..{MAX_RATE_RPS} rps (got {rate})")


def check_port_scan_limits(ports: list[int], threads: int, rate: float) -> None:
    if len(ports) > 1000:
        raise SafetyError("refusing to scan more than 1000 ports in one run")
    if threads < 1 or threads > MAX_CONCURRENCY:
        raise SafetyError(f"--threads must be 1..{MAX_CONCURRENCY}")
    if rate > MAX_RATE_RPS:
        raise SafetyError(f"scan rate too high (max {MAX_RATE_RPS} rps)")


def sanitize_for_log(value: str) -> str:
    """Redact anything that looks like a secret before logging."""
    import re

    redacted = re.sub(r"(?i)(password|passwd|pwd|token|secret|api[_-]?key|session|cookie)\s*[:=]\s*\S+", r"\1=***", value)
    return redacted[:500]
