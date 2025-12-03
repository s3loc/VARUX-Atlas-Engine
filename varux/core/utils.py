"""Common helper routines for VARUX components."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict

import yaml


def ensure_directory(path: Path) -> Path:
    """Ensure ``path`` exists and return it."""

    path.mkdir(parents=True, exist_ok=True)
    return path


def load_yaml(path: Path) -> Dict[str, Any]:
    """Load a YAML file returning an empty dict on failure."""

    try:
        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    except FileNotFoundError:
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
