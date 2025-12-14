"""Environment diagnostics helpers for VARUX.

The diagnostics layer validates that critical third‑party dependencies,
executables, and environment variables are available before the operator
launches the heavier modules. It is intentionally dependency‑light and
uses ``importlib``/``shutil`` lookups instead of importing large
frameworks so that it can safely run on constrained systems.
"""
from __future__ import annotations

import importlib.util
import platform
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional


@dataclass
class CheckResult:
    """Represents the outcome of a single diagnostic check."""

    name: str
    ok: bool
    detail: str


@dataclass
class DiagnosticsReport:
    """Aggregated diagnostics data with helper views."""

    timestamp: datetime = field(default_factory=datetime.utcnow)
    platform_info: str = field(default_factory=platform.platform)
    python_version: str = field(default_factory=platform.python_version)
    checks: List[CheckResult] = field(default_factory=list)

    def add_check(self, name: str, ok: bool, detail: str) -> None:
        self.checks.append(CheckResult(name=name, ok=ok, detail=detail))

    @property
    def summary(self) -> dict:
        total = len(self.checks)
        passed = sum(1 for check in self.checks if check.ok)
        failed = total - passed
        return {"total": total, "passed": passed, "failed": failed}

    def format_as_table(self) -> str:
        """Return a simple table summarizing the diagnostics."""

        lines = [
            "Sistem Tanısı Raporu",
            f"Tarih (UTC): {self.timestamp.isoformat()} | Python: {self.python_version}",
            f"Platform: {self.platform_info}",
            "",
            "Kontrol                                Durum   Ayrıntı",
            "-------------------------------------------------------------",
        ]
        for check in self.checks:
            status = "OK" if check.ok else "HATA"
            lines.append(f"{check.name:<38} {status:<6} {check.detail}")
        lines.append("-------------------------------------------------------------")
        summary = self.summary
        lines.append(
            f"Toplam: {summary['total']} | Başarılı: {summary['passed']} | Başarısız: {summary['failed']}"
        )
        return "\n".join(lines)


def _module_available(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _check_modules(report: DiagnosticsReport, modules: Iterable[str]) -> None:
    for mod in modules:
        available = _module_available(mod)
        detail = "Yüklü" if available else "Eksik (pip install önerilir)"
        report.add_check(f"Modül: {mod}", available, detail)


def _check_binaries(report: DiagnosticsReport, binaries: Iterable[str]) -> None:
    for binary in binaries:
        path = shutil.which(binary)
        report.add_check(
            f"Araç: {binary}",
            path is not None,
            path if path else "Sistemde bulunamadı",
        )


def _check_env_vars(report: DiagnosticsReport, env_vars: Iterable[str]) -> None:
    import os

    for var in env_vars:
        value = os.getenv(var)
        report.add_check(
            f"Env: {var}",
            bool(value),
            "Tanımlı" if value else "Eksik",
        )


def _check_paths(report: DiagnosticsReport, paths: Iterable[Path]) -> None:
    for path in paths:
        expanded = path.expanduser()
        if expanded.exists():
            detail = "Okunabilir" if expanded.is_file() else "Dizin hazır"
            report.add_check(f"Yol: {expanded}", True, detail)
        else:
            report.add_check(f"Yol: {expanded}", False, "Bulunamadı")


def run_diagnostics(
    modules: Optional[Iterable[str]] = None,
    env_vars: Optional[Iterable[str]] = None,
    binaries: Optional[Iterable[str]] = None,
    paths: Optional[Iterable[Path | str]] = None,
) -> DiagnosticsReport:
    """Execute a suite of environment checks.

    Parameters are overridable for testing or custom runs; defaults cover
    the most critical VARUX dependencies.
    """

    report = DiagnosticsReport()

    module_list = list(modules) if modules is not None else [
        "scapy",
        "pysnmp",
        "dash",
        "plotly",
        "colorama",
    ]
    env_list = list(env_vars) if env_vars is not None else ["OPENAI_API_KEY"]
    binary_list = list(binaries) if binaries is not None else ["sqlmap"]
    path_list = [Path(p) for p in paths] if paths is not None else []

    _check_modules(report, module_list)
    _check_binaries(report, binary_list)
    _check_env_vars(report, env_list)
    _check_paths(report, path_list)

    return report


__all__ = ["CheckResult", "DiagnosticsReport", "run_diagnostics"]
