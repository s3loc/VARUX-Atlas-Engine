"""Configuration management utilities for VARUX components.

This module centralizes configuration loading and saving so that the
individual tools can share consistent defaults. It provides a
``ConfigManager`` helper that reads YAML or JSON files, merges them with a
safe default configuration, and exposes ``get``/``set`` helpers that work
with dot-notation keys.
"""
from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from .utils import load_json, load_yaml, save_json, save_yaml

logger = logging.getLogger(__name__)


class ConfigManager:
    """Load and persist configuration files with sane defaults."""

    ENV_CONFIG_PATH = "VARUX_CONFIG_PATH"

    def __init__(self, config_path: Optional[Path | str] = None):
        env_path = os.getenv(self.ENV_CONFIG_PATH)
        self.config_path: Path = Path(
            config_path
            or env_path
            or (Path.home() / ".varux" / "config.yaml")
        ).expanduser()
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config: Dict[str, Any] = {}
        self.reset_to_defaults()
        self.load()

    @staticmethod
    def default_config() -> Dict[str, Any]:
        """Base configuration used when no file is present."""

        return {
            "global": {
                "log_level": "INFO",
                "max_concurrent_tasks": 10,
                "default_timeout": 30,
                "max_retries": 3,
            },
            "ai": {
                "provider": "openai",
                "model": "gpt-4o-mini",
                "api_key_env": "VARUX_AI_API_KEY",
                "timeout": 30,
                "rate_limit": {
                    "requests_per_minute": 60,
                    "burst_limit": 10,
                },
            },
            "scan": {
                "rate_limit": {
                    "requests_per_second": 10,
                    "max_concurrent_requests": 20,
                    "burst_limit": 5,
                },
                "timeouts": {"connect": 10, "read": 30, "total": 300},
                "user_agent": "VARUX-Security-Scanner/6.0",
                "follow_redirects": True,
                "verify_ssl": False,
                "max_redirects": 10,
                "throttle_delay": 0.1,
            },
            "storage": {"output_dir": str(Path.home() / "varux_outputs")},
            "compliance": {
                "terms_accepted": False,
                "mode": "passive",
                "accepted_at": None,
            },
        }

    def reset_to_defaults(self) -> None:
        """Reset the in-memory config to the default values."""

        self.config = self.default_config()

    def load(self) -> None:
        """Load configuration from disk if a file is available."""

        if not self.config_path.exists():
            logger.debug("Config file %s not found; using defaults", self.config_path)
            return

        try:
            file_config = (
                load_yaml(self.config_path)
                if self.config_path.suffix.lower() in {".yaml", ".yml"}
                else load_json(self.config_path)
            )
            if isinstance(file_config, dict):
                self._deep_merge(self.config, file_config)
                logger.info("Configuration loaded from %s", self.config_path)
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.error("Failed to load configuration: %s", exc)

    def save(self) -> bool:
        """Persist the current configuration to disk.

        Returns ``True`` when the configuration is successfully written.
        """

        try:
            if self.config_path.suffix.lower() in {".yaml", ".yml"}:
                save_yaml(self.config_path, self.config)
            else:
                save_json(self.config_path, self.config)
            self.config_path.chmod(0o600)
            logger.info("Configuration saved to %s", self.config_path)
            return True
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.error("Failed to save configuration: %s", exc)
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """Return a configuration value using dot-notation keys."""

        current: Any = self.config
        for part in key.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default
        return current

    def set(self, key: str, value: Any) -> bool:
        """Set a configuration value using dot-notation keys."""

        current = self.config
        parts = key.split(".")
        try:
            for part in parts[:-1]:
                current = current.setdefault(part, {})
                if not isinstance(current, dict):
                    raise ValueError(f"Intermediate key '{part}' is not a mapping")
            current[parts[-1]] = value
            return True
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.error("Failed to set configuration key %s: %s", key, exc)
            return False

    def _deep_merge(self, dest: Dict[str, Any], src: Dict[str, Any]) -> None:
        """Recursively merge ``src`` into ``dest`` in-place."""

        for key, value in src.items():
            if isinstance(value, dict) and isinstance(dest.get(key), dict):
                self._deep_merge(dest[key], value)
            else:
                dest[key] = value


__all__ = ["ConfigManager"]
