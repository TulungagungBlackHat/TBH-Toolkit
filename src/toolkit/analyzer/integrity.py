"""Web Integrity & Security Analyzer (defensive replacement for DEFACE WebDAV PUT).

Never uploads or modifies a remote target. Only hashes local files,
builds a baseline, and reports NEW / MODIFIED / DELETED / SUSPICIOUS.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

SUSPICIOUS_PATTERNS = [
    (re.compile(r"<iframe[^>]+src\s*=\s*['\"]http", re.IGNORECASE), "external-iframe"),
    (re.compile(r"<script[^>]+src\s*=\s*['\"]http", re.IGNORECASE), "external-script"),
    (re.compile(r"(?i)(eval\s*\(|fromcharcode|unescape\s*\(|document\.write\s*\(|powershell|cmd\.exe|/bin/(ba)?sh)"), "obfuscated-code"),
    (re.compile(r"(?i)deface|hacked by|owned by"), "deface-graffiti"),
]

TEXT_EXTS = {".html", ".htm", ".js", ".css", ".php", ".txt", ".json", ".xml", ".svg"}


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class IntegrityRecord:
    path: str
    sha256: str
    size: int
    suspicious: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def scan_file(p: Path) -> list[str]:
    if p.suffix.lower() not in TEXT_EXTS:
        return []
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")[:200000]
    except OSError:
        return []
    hits = [name for rx, name in SUSPICIOUS_PATTERNS if rx.search(text)]
    return hits


def build_baseline(root: str | Path) -> dict:
    root_p = Path(root)
    records = []
    for f in sorted(root_p.rglob("*")):
        if f.is_file() and ".git" not in f.parts:
            try:
                records.append(IntegrityRecord(
                    path=str(f.relative_to(root_p)), sha256=sha256_file(f),
                    size=f.stat().st_size, suspicious=scan_file(f)))
            except OSError:
                continue
    return {"root": str(root_p), "created_at": datetime.now(UTC).isoformat(),
            "files": [r.to_dict() for r in records]}


def check_against_baseline(root: str | Path, baseline: dict) -> dict:
    root_p = Path(root)
    old = {f["path"]: f for f in baseline.get("files", [])}
    current = {f["path"]: f for f in build_baseline(root)["files"]}
    new = sorted(set(current) - set(old))
    deleted = sorted(set(old) - set(current))
    modified = sorted(p for p in set(old) & set(current) if old[p]["sha256"] != current[p]["sha256"])
    suspicious = sorted(p for p, rec in current.items() if rec["suspicious"])
    return {"root": str(root_p), "checked_at": datetime.now(UTC).isoformat(),
            "NEW": new, "MODIFIED": modified, "DELETED": deleted, "SUSPICIOUS": suspicious,
            "counts": {"new": len(new), "modified": len(modified), "deleted": len(deleted),
                       "suspicious": len(suspicious), "total": len(current)},
            "details": {p: current[p] for p in (suspicious + modified[:20]) if p in current}}
