"""Centralized logging.

We expose a single `get_logger()` helper so every module logs the same way,
and a `MemoryLogHandler` that the UI can read from to show live logs.
"""

from __future__ import annotations

import logging
from collections import deque
from pathlib import Path
from typing import Deque

_CONFIGURED = False
_MEM_HANDLER: "MemoryLogHandler | None" = None


class MemoryLogHandler(logging.Handler):
    """Keeps the last N formatted log lines in memory for the UI to poll."""

    def __init__(self, capacity: int = 500) -> None:
        super().__init__()
        self.buffer: Deque[str] = deque(maxlen=capacity)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.buffer.append(self.format(record))
        except Exception:  # pragma: no cover — never let logging crash callers
            self.handleError(record)

    def drain(self) -> list[str]:
        """Return and clear all pending lines."""
        lines = list(self.buffer)
        self.buffer.clear()
        return lines


def configure(log_file: Path | None = None, level: int = logging.INFO) -> None:
    """Configure root logging. Safe to call multiple times."""
    global _CONFIGURED, _MEM_HANDLER
    if _CONFIGURED:
        return

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(level)

    # Console
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    root.addHandler(ch)

    # File (optional)
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)

    # Memory (for UI)
    _MEM_HANDLER = MemoryLogHandler()
    _MEM_HANDLER.setFormatter(fmt)
    root.addHandler(_MEM_HANDLER)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    if not _CONFIGURED:
        configure()
    return logging.getLogger(name)


def memory_handler() -> MemoryLogHandler:
    if _MEM_HANDLER is None:
        configure()
    assert _MEM_HANDLER is not None
    return _MEM_HANDLER
