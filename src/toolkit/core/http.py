"""Shared HTTP client: timeout, retries with backoff, safe UA, no secret logging."""
from __future__ import annotations

import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def build_session(timeout: float = 8.0, user_agent: str = "TBH-Toolkit/1.0", retries: int = 2) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": user_agent})
    retry = Retry(
        total=retries, backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    # stash default timeout for helpers
    s.request_timeout = timeout  # type: ignore[attr-defined]
    return s


def get(session: requests.Session, url: str, timeout: float | None = None, **kw: Any) -> requests.Response:
    to = timeout if timeout is not None else getattr(session, "request_timeout", 8.0)
    kw.setdefault("timeout", to)
    return session.get(url, **kw)


def request_with_backoff(session: requests.Session, method: str, url: str,
                         timeout: float = 8.0, max_attempts: int = 3, **kw: Any) -> requests.Response:
    """Extra manual backoff for connection errors (on top of urllib3 retries)."""
    last: Exception | None = None
    for attempt in range(max_attempts):
        try:
            kw.setdefault("timeout", timeout)
            return session.request(method, url, **kw)
        except (requests.ConnectionError, requests.Timeout) as e:
            last = e
            time.sleep(min(2.0 ** attempt * 0.5, 4.0))
    assert last is not None
    raise last
