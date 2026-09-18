"""Authorized load testing (NOT a DDoS tool).

Replaces legacy uchil404-ddos (infinite Hammer flood) with a bounded,
rate-limited, allowlisted load probe for localhost/lab that reports
latency/throughput/status distribution and stops on circuit-breaker.
"""
from __future__ import annotations

import statistics
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from ..core.http import build_session
from ..core.safety import check_loadtest_limits


@dataclass
class LoadStats:
    target: str
    requests: int = 0
    concurrency: int = 1
    rate_rps: float = 1.0
    latencies_ms: list[float] = field(default_factory=list)
    statuses: Counter = field(default_factory=Counter)
    errors: int = 0
    started_at: str = ""
    duration_s: float = 0.0

    def summary(self) -> dict:
        lat = sorted(self.latencies_ms)
        def pct(p: float) -> float:
            if not lat:
                return 0.0
            idx = min(len(lat) - 1, int(p / 100 * len(lat)))
            return round(lat[idx], 2)
        total = max(self.duration_s, 0.001)
        return {
            "target": self.target, "requests": self.requests, "concurrency": self.concurrency,
            "rate_rps": self.rate_rps, "duration_s": round(self.duration_s, 2),
            "rps": round(len(lat) / total, 2), "errors": self.errors,
            "error_rate": round(self.errors / max(len(lat) + self.errors, 1), 4),
            "status_distribution": dict(self.statuses),
            "latency_ms": {
                "min": round(min(lat), 2) if lat else 0.0, "mean": round(statistics.mean(lat), 2) if lat else 0.0,
                "p50": pct(50), "p90": pct(90), "p99": pct(99), "max": round(max(lat), 2) if lat else 0.0,
            },
        }


def run_loadtest(target: str, requests_n: int = 100, concurrency: int = 5,
                 rate: float = 2.0, timeout: float = 8.0,
                 user_agent: str = "TBH-Toolkit-loadtest/1.0",
                 path: str = "/") -> LoadStats:
    check_loadtest_limits(requests_n, concurrency, rate)
    base = target if target.startswith(("http://", "https://")) else "http://" + target
    url = base.rstrip("/") + path
    host = urlparse(base).hostname or target
    stats = LoadStats(target=url, requests=requests_n, concurrency=concurrency,
                      rate_rps=rate, started_at=datetime.now(timezone.utc).isoformat())
    session = build_session(timeout=timeout, user_agent=user_agent)
    gap = 1.0 / max(rate, 0.1)
    lock = threading.Lock()
    stop = threading.Event()
    consecutive_errors = 0
    t0 = time.time()

    def one(i: int) -> None:
        nonlocal consecutive_errors
        if stop.is_set():
            return
        time.sleep(gap * (i % max(concurrency, 1)) / max(concurrency, 1))
        t = time.time()
        try:
            r = session.get(url, timeout=timeout)
            ms = (time.time() - t) * 1000
            with lock:
                stats.latencies_ms.append(ms)
                stats.statuses[r.status_code] += 1
                consecutive_errors = 0
                if r.status_code >= 500:
                    consecutive_errors += 1
        except requests.RequestException:
            with lock:
                stats.errors += 1
                consecutive_errors += 1
        if consecutive_errors >= 10:
            stop.set()  # circuit breaker: target is struggling, stop hammering

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        list(ex.map(one, range(requests_n)))
    stats.duration_s = time.time() - t0
    return stats
