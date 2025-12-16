"""Terms-of-use enforcement utilities shared by CLI and dashboard.

This module tracks consent decisions in the persistent configuration
location (``~/.varux`` by default) and writes a simple JSONL audit log for
visibility. The helper is intentionally lightweight to avoid adding new
runtime dependencies while still keeping a durable record of user
choices.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from .config import ConfigManager
from .utils import ensure_directory

TERMS_NOTICE = """
VARUX Atlas Engine Kullanım Şartları ve Pasif Tarama Uyarısı
-----------------------------------------------------------
- VARUX yalnızca yetkilendirilmiş ortamlarda kullanılabilir.
- Varsayılan çalışma modu pasif keşiftir; aktif taramalarda yasal ve
  operasyonel riskler doğabilir.
- Aktif modları açmadan önce ilgili sistem sahiplerinden izin almak
  sizin sorumluluğunuzdadır.
- Kabul etmediğiniz sürece modüller çalıştırılamaz ve tüm denemeler audit
  kaydına geçer.
"""


class TermsManager:
    """Persist consent decisions and emit audit logs."""

    def __init__(self, source: str = "cli") -> None:
        self.source = source
        self.config = ConfigManager()
        self.audit_file: Path = ensure_directory(self.config.config_path.parent) / "audit.log"

    def get_status(self) -> Dict[str, Any]:
        """Return the current consent status."""

        return {
            "accepted": bool(self.config.get("compliance.terms_accepted", False)),
            "mode": self.config.get("compliance.mode", "passive"),
            "accepted_at": self.config.get("compliance.accepted_at"),
        }

    def record_decision(self, accepted: bool, mode: str = "passive") -> None:
        """Persist a consent decision and append an audit entry."""

        timestamp = datetime.utcnow().isoformat()
        self.config.set("compliance.terms_accepted", accepted)
        self.config.set("compliance.mode", mode)
        self.config.set("compliance.accepted_at", timestamp if accepted else None)
        self.config.save()
        self._append_audit_entry(accepted, mode, timestamp)

    def _append_audit_entry(self, accepted: bool, mode: str, timestamp: str) -> None:
        entry = {
            "timestamp": timestamp,
            "decision": "accepted" if accepted else "declined",
            "mode": mode,
            "source": self.source,
        }
        ensure_directory(self.audit_file.parent)
        with self.audit_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


__all__ = ["TermsManager", "TERMS_NOTICE"]
