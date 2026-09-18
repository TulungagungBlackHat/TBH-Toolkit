"""TOML config file: ~/.config/toolkit/config.toml + env overrides."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11 fallback (not expected)
    tomllib = None  # type: ignore[assignment]


@dataclass
class ToolkitConfig:
    timeout: float = 8.0
    concurrency: int = 5
    rate_rps: float = 2.0
    user_agent: str = "TBH-Toolkit/1.0 (+authorized-lab-use)"
    output_dir: str = "reports"
    log_level: str = "INFO"
    max_requests: int = 500
    max_concurrency: int = 10
    allow_external: bool = False

    @classmethod
    def default_path(cls) -> Path:
        return Path(os.environ.get("TOOLKIT_CONFIG", str(Path.home() / ".config" / "toolkit" / "config.toml")))

    @classmethod
    def load(cls, path: str | Path | None = None) -> "ToolkitConfig":
        cfg = cls()
        p = Path(path) if path else cls.default_path()
        if p.is_file() and tomllib is not None:
            try:
                data = tomllib.loads(p.read_text(encoding="utf-8"))
                section = data.get("toolkit", data)
                for f in ("timeout", "concurrency", "rate_rps", "user_agent", "output_dir", "log_level",
                          "max_requests", "max_concurrency", "allow_external"):
                    if f in section:
                        setattr(cfg, f, section[f])
            except OSError:
                pass
        # Env overrides (never secrets in repo; only non-secret tuning here)
        if os.environ.get("TOOLKIT_TIMEOUT"):
            cfg.timeout = float(os.environ["TOOLKIT_TIMEOUT"])
        if os.environ.get("TOOLKIT_USER_AGENT"):
            cfg.user_agent = os.environ["TOOLKIT_USER_AGENT"]
        if os.environ.get("TOOLKIT_OUTPUT_DIR"):
            cfg.output_dir = os.environ["TOOLKIT_OUTPUT_DIR"]
        # Clamp to safety bounds
        cfg.concurrency = max(1, min(cfg.concurrency, cfg.max_concurrency))
        cfg.rate_rps = max(0.1, min(cfg.rate_rps, 50.0))
        cfg.timeout = max(1.0, min(cfg.timeout, 60.0))
        return cfg

    def to_dict(self) -> dict:
        return {
            "timeout": self.timeout, "concurrency": self.concurrency, "rate_rps": self.rate_rps,
            "user_agent": self.user_agent, "output_dir": self.output_dir, "log_level": self.log_level,
            "max_requests": self.max_requests, "max_concurrency": self.max_concurrency,
            "allow_external": self.allow_external,
        }


DEFAULT_TOML = """\
# TBH Security Toolkit config (~/.config/toolkit/config.toml)
[toolkit]
timeout = 8.0
concurrency = 5
rate_rps = 2.0
user_agent = "TBH-Toolkit/1.0 (+authorized-lab-use)"
output_dir = "reports"
log_level = "INFO"
max_requests = 500
max_concurrency = 10
allow_external = false
"""
