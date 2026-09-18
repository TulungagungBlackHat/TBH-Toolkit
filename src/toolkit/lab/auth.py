"""Authentication Security Lab (defensive replacement for darkfb credential attacks).

No real accounts, no network login, no password transmission. Local-only
simulators for password policy, lockout/rate-limit, session/CSRF concepts,
plus a tiny vulnerable demo app (runs on 127.0.0.1) for classroom testing.
"""
from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass, field

COMMON = {"123456", "password", "qwerty", "admin", "12345678", "iloveyou", "letmein", "welcome"}


def password_audit(pwd: str) -> dict:
    adv = []
    score = 0
    if len(pwd) >= 12:
        score += 2
    elif len(pwd) >= 8:
        score += 1
    else:
        adv.append("Use at least 12 characters")
    for rx, label in [(r"[A-Z]", "uppercase"), (r"[a-z]", "lowercase"), (r"[0-9]", "digit"), (r"[^A-Za-z0-9]", "symbol")]:
        if re.search(rx, pwd):
            score += 1
        else:
            adv.append(f"Add {label} characters")
    if pwd.lower() in COMMON:
        score = 0
        adv.append("Too common - pick an unrelated passphrase")
    score = max(0, min(6, score))
    verdict = "STRONG" if score >= 5 else "OK" if score >= 3 else "WEAK"
    return {"score": score, "max": 6, "verdict": verdict, "advice": adv, "length": len(pwd)}


@dataclass
class LockoutSimulator:
    """Simulate rate-limit + lockout + brute-force detection locally."""
    max_attempts: int = 5
    lockout_seconds: float = 60.0
    attempts: int = 0
    locked_until: float = 0.0
    log: list[dict] = field(default_factory=list)

    def attempt(self, correct: bool) -> dict:
        now = time.time()
        if now < self.locked_until:
            self.log.append({"t": now, "result": "blocked", "reason": "locked"})
            return {"result": "blocked", "retry_after_s": round(self.locked_until - now, 1)}
        self.attempts += 1
        if correct:
            self.attempts = 0
            self.log.append({"t": now, "result": "success"})
            return {"result": "success"}
        self.log.append({"t": now, "result": "fail", "attempt": self.attempts})
        if self.attempts >= self.max_attempts:
            self.locked_until = now + self.lockout_seconds
            self.log.append({"t": now, "result": "locked"})
            return {"result": "locked", "retry_after_s": self.lockout_seconds,
                    "lesson": "Attacker is now throttled; real systems also alert + require MFA/captcha."}
        return {"result": "fail", "remaining": self.max_attempts - self.attempts}


def generate_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


CSRF_LESSON = """CSRF lab: a state-changing request must require an unguessable per-session
token (Synchronizer Token Pattern) + SameSite cookies. GET must never mutate state."""


def demo_app_html() -> str:
    return """<!doctype html><html><body style='font-family:monospace'>
<h1>TBH Auth Lab - intentionally vulnerable demo (127.0.0.1 only)</h1>
<form method=POST action=/login>user <input name=user> pass <input name=pass type=password>
<input type=submit value=Login></form>
<p>Lesson: this form has NO rate-limit, NO lockout, NO CSRF token, weak session cookie.
Harden it, then re-test with: toolkit lab auth-audit</p></body></html>"""
