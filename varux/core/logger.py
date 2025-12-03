"""Logging helpers shared across VARUX components."""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

DEFAULT_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"


def setup_logging(level: str = "INFO", log_file: Optional[Path | str] = None) -> None:
    """Configure the root logger with console and optional file handlers."""

    root_logger = logging.getLogger()
    if root_logger.handlers:
        return  # Avoid configuring logging multiple times

    log_level = getattr(logging, level.upper(), logging.INFO)
    root_logger.setLevel(log_level)

    formatter = logging.Formatter(DEFAULT_FORMAT)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    if log_file:
        log_path = Path(log_file).expanduser()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024, backupCount=3)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)


def get_logger(name: Optional[str] = None, level: str = "INFO", log_file: Optional[Path | str] = None) -> logging.Logger:
    """Return a configured logger instance."""

    setup_logging(level=level, log_file=log_file)
    return logging.getLogger(name)


__all__ = ["setup_logging", "get_logger"]
