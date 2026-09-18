"""Shared finding model with severity, evidence, remediation."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

SEVERITY_ORDER: dict[str, int] = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    endpoint: str = ""
    evidence: str = ""
    explanation: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    module: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    module: str
    started_at: str = ""
    duration_s: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "module": self.module,
            "started_at": self.started_at,
            "duration_s": self.duration_s,
            "meta": self.meta,
            "findings": [f.to_dict() for f in self.findings],
        }

    def highest_severity(self) -> Severity:
        if not self.findings:
            return "INFO"
        return max(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity  # type: ignore[return-value]
