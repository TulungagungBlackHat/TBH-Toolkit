"""Safe utilities (TBH-Utils lineage): base64/url/hash/qr helpers, no secrets logged."""
from __future__ import annotations
import base64, hashlib, urllib.parse
def b64e(t: str) -> str: return base64.b64encode(t.encode()).decode()
def b64d(t: str) -> str: return base64.b64decode(t).decode()
def urle(t: str) -> str: return urllib.parse.quote(t)
def urld(t: str) -> str: return urllib.parse.unquote(t)
def hashes(t: str) -> dict: return {"md5": hashlib.md5(t.encode()).hexdigest(), "sha256": hashlib.sha256(t.encode()).hexdigest()}
