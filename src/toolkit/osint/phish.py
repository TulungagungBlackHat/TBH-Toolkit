"""Defensive OSINT helpers: phishing-URL heuristics + username hygiene (no doxxing)."""
from __future__ import annotations

import re
from urllib.parse import urlparse


def analyze_url(url: str) -> dict:
    score = 0
    reasons: list[str] = []
    u = url if url.startswith("http") else "https://" + url
    p = urlparse(u)
    domain = p.netloc.lower()
    full = u
    if re.match(r"^\d+\.\d+\.\d+\.\d+", domain.split(":")[0]):
        score += 3; reasons.append("IP address instead of domain")
    if len(full) > 75:
        score += 1; reasons.append(f"Unusually long URL ({len(full)} chars)")
    if "@" in full:
        score += 2; reasons.append("'@' trick (credentials@host)")
    if any(domain.endswith(t) for t in (".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz")):
        score += 2; reasons.append("High-abuse TLD")
    if "xn--" in domain:
        score += 3; reasons.append("Punycode (possible homograph)")
    try:
        domain.encode("ascii")
    except UnicodeEncodeError:
        score += 3; reasons.append("Non-ASCII domain")
    if not u.startswith("https"):
        score += 1; reasons.append("No HTTPS")
    if any(k in domain for k in ("login", "verify", "secure", "account", "update")) and len(domain.split(".")) > 3:
        score += 1; reasons.append("Deep subdomain + lure keyword")
    verdict = "PHISHING-LIKE" if score >= 5 else "SUSPICIOUS" if score >= 3 else "LIKELY-BENIGN"
    return {"url": url, "score": score, "verdict": verdict, "reasons": reasons,
            "advice": "Verify sender, hover links, use TBH-PhishDetector lineage: never enter credentials from chat links."}
