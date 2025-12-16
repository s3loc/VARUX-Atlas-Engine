"""Module registry shared between CLI, dashboard and orchestrator.

This file centralizes the metadata needed to dynamically import and invoke
the built-in VARUX modules. Keeping the registry in a single place ensures
that the CLI, dashboard and the new task orchestrator enqueue the exact
same targets and entrypoints.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict

MODULE_REGISTRY: Dict[str, dict] = {
    "industrial_recon": {
        "file": "industrial_recon.py",
        "function": "main",
        "async": False,
        "description": "Endüstriyel ağ pasif/aktif keşif",
    },
    "noxım": {
        "file": "noxım.py",
        "function": "main",
        "async": False,
        "description": "Web ve SQLi odaklı tarama",
    },
    "varuxctl": {
        "file": "varuxctl.py",
        "function": "main",
        "async": True,
        "description": "Tam otomatik saldırı simülasyonu",
    },
    "ot_discovery": {
        "file": "VARUX OT Discovery Framework.py",
        "function": "main_enhanced",
        "async": True,
        "description": "ICS/SCADA topoloji ve varlık keşfi",
    },
    "sqlmap_wrapper": {
        "file": "sqlmap_wrapper.py",
        "function": "run_advanced_scan",
        "async": False,
        "description": "SQLMap elit sarmalayıcı ile otomatik zafiyet analizi",
        "class": "SQLMapWrapper",
    },
    "ai_assistant": {
        "file": "ai_assistant.py",
        "function": "generate_assistance",
        "async": False,
        "description": "OpenAI destekli güvenlik/kod asistanı",
        "class": "AIAssistant",
    },
}


def module_path(base_dir: Path, module_key: str) -> Path:
    """Return the fully qualified path for the requested module."""

    module_info = MODULE_REGISTRY[module_key]
    return base_dir / module_info["file"]


__all__ = ["MODULE_REGISTRY", "module_path"]
