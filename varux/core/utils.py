"""Common helper routines for VARUX components."""
from __future__ import annotations

import hashlib
import json
import logging
from json import JSONDecodeError
from pathlib import Path
from typing import Any, Dict

try:  # PyYAML is preferred but we ship a minimal JSON-based fallback
    import yaml
    from yaml import YAMLError
except ModuleNotFoundError:  # pragma: no cover - exercised in constrained envs
    class _YamlShim:
        class YAMLError(Exception):
            ...

        @staticmethod
        def safe_load(stream):
            if hasattr(stream, "read"):
                stream = stream.read()
            if not stream:
                return {}
            return json.loads(stream)

        @staticmethod
        def safe_dump(data, handle, default_flow_style=False, indent=2):
            if hasattr(handle, "write"):
                handle.write(json.dumps(data, indent=indent))
            else:
                return json.dumps(data, indent=indent)

    yaml = _YamlShim()  # type: ignore[assignment]
    YAMLError = _YamlShim.YAMLError

logger = logging.getLogger(__name__)


def ensure_directory(path: Path) -> Path:
    """Ensure ``path`` exists and return it."""

    path.mkdir(parents=True, exist_ok=True)
    return path


def load_yaml(path: Path) -> Dict[str, Any]:
    """Load a YAML file returning an empty dict on failure.

    The helper is deliberately tolerant: malformed or missing files
    should not crash the caller, so errors are logged and an empty
    dictionary is returned instead.
    """

    try:
        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    except FileNotFoundError:
        return {}
    except (YAMLError, OSError, JSONDecodeError) as exc:
        logger.warning("Failed to parse YAML %s: %s", path, exc)
        return {}


def save_yaml(path: Path, data: Dict[str, Any]) -> None:
    """Persist ``data`` to ``path`` using safe YAML dumping."""

    ensure_directory(path.parent)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, default_flow_style=False, indent=2)


def load_json(path: Path) -> Dict[str, Any]:
    """Load JSON data returning an empty dict on failure."""

    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return {}
    except (JSONDecodeError, OSError) as exc:
        logger.warning("Failed to parse JSON %s: %s", path, exc)
        return {}


def save_json(path: Path, data: Dict[str, Any]) -> None:
    """Persist ``data`` to ``path`` in JSON format."""

    ensure_directory(path.parent)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def hash_file(path: Path, algorithm: str = "sha256") -> str:
    """Return a hex digest for the provided file path."""

    hasher = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


__all__ = [
    "ensure_directory",
    "load_yaml",
    "save_yaml",
    "load_json",
    "save_json",
    "hash_file",
]
