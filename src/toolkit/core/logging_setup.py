"""Structured logging without secret leakage."""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

from .safety import sanitize_for_log

_configured = False


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": record.name,
            "msg": sanitize_for_log(record.getMessage()),
        }
        if hasattr(record, "extra_fields"):
            payload.update(getattr(record, "extra_fields"))  # type: ignore[union-attr]
        return json.dumps(payload)


def setup_logging(level: str = "INFO", json_logs: bool = False) -> logging.Logger:
    global _configured
    logger = logging.getLogger("toolkit")
    if _configured:
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        return logger
    handler = logging.StreamHandler(sys.stderr)
    if json_logs:
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.handlers = [handler]
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False
    _configured = True
    return logger


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"toolkit.{name}")
