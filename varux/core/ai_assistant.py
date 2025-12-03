"""AI assistant utilities that respect centralized configuration.

The assistant pulls provider settings from :class:`~varux.core.config.ConfigManager`
using its ``get``/``set`` helpers so that defaults can be overridden by YAML or
JSON config files. Secrets (API keys) are loaded from environment variables or
optional external files rather than being embedded in code.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from .config import ConfigManager

logger = logging.getLogger(__name__)


class AIAssistant:
    """Load AI provider settings from the shared configuration manager."""

    def __init__(self, config_manager: Optional[ConfigManager] = None) -> None:
        self.config_manager = config_manager or ConfigManager()
        self.refresh_settings()

    def refresh_settings(self) -> None:
        """Refresh cached settings from the current configuration state."""

        self.provider: str = self.config_manager.get("ai.provider", "")
        self.model: str = self.config_manager.get("ai.model", "")
        self.api_key_env: Optional[str] = self.config_manager.get("ai.api_key_env")
        self.timeout: int = self.config_manager.get("ai.timeout", 30)
        self.rate_limit: Dict[str, Any] = self.config_manager.get("ai.rate_limit", {})

    def get_api_key(self) -> Optional[str]:
        """Return the AI provider API key from a safe source.

        Priority is given to environment variables defined by ``ai.api_key_env``.
        As a fallback, the assistant can read from an optional file path
        ``ai.api_key_file`` so that keys remain outside version control.
        """

        if self.api_key_env:
            api_key = os.getenv(self.api_key_env)
            if api_key:
                return api_key
            logger.debug("Environment variable %s for AI API key is not set", self.api_key_env)

        api_key_file = self.config_manager.get("ai.api_key_file")
        if api_key_file:
            path = Path(api_key_file).expanduser()
            try:
                return path.read_text(encoding="utf-8").strip()
            except FileNotFoundError:
                logger.warning("Configured AI API key file %s not found", path)
            except OSError as exc:  # pragma: no cover - defensive logging
                logger.error("Failed to read AI API key file %s: %s", path, exc)
        return None

    def update_model(self, model: str) -> bool:
        """Persist a new model choice using the config manager."""

        if self.config_manager.set("ai.model", model):
            self.model = model
            return True
        return False

    def update_provider(self, provider: str) -> bool:
        """Persist a new provider selection using the config manager."""

        if self.config_manager.set("ai.provider", provider):
            self.provider = provider
            return True
        return False

    def request_settings(self) -> Dict[str, Any]:
        """Return a sanitized snapshot of AI request configuration."""

        return {
            "provider": self.provider,
            "model": self.model,
            "timeout": self.timeout,
            "rate_limit": self.rate_limit,
            "api_key": self.get_api_key(),
        }


__all__ = ["AIAssistant"]
