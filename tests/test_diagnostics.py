from pathlib import Path

from varux.core.diagnostics import run_diagnostics


def _result_map(report):
    return {check.name: check for check in report.checks}


def test_diagnostics_supports_custom_inputs(monkeypatch, tmp_path):
    monkeypatch.setenv("VARUX_TEST_ENV", "true")

    report = run_diagnostics(
        modules=["json", "nonexistent_fake_module"],
        env_vars=["VARUX_TEST_ENV", "MISSING_VAR"],
        binaries=[],
        paths=[tmp_path, tmp_path / "missing.txt"],
    )

    results = _result_map(report)
    assert results["Modül: json"].ok is True
    assert results["Modül: nonexistent_fake_module"].ok is False
    assert results["Env: VARUX_TEST_ENV"].ok is True
    assert results["Env: MISSING_VAR"].ok is False
    assert results[f"Yol: {tmp_path}"].ok is True
    assert results[f"Yol: {tmp_path / 'missing.txt'}"].ok is False


def test_diagnostics_summary_counts(monkeypatch):
    report = run_diagnostics(modules=["json"], env_vars=[], binaries=[], paths=[])
    summary = report.summary

    assert summary["total"] == len(report.checks)
    assert summary["passed"] == summary["total"]
    assert summary["failed"] == 0
