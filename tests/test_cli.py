"""CLI smoke tests via Typer's CliRunner (no external services)."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from attack_engine.cli import app
from attack_engine.config import reset_settings_cache

runner = CliRunner()
EXAMPLE_SCOPE = Path(__file__).resolve().parents[1] / "examples/engagement-range.scope.yaml"


@pytest.fixture(autouse=True)
def _in_memory_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the CLI onto zero-dependency backends for the duration of a test."""

    monkeypatch.setenv("AE_MODEL_MOCK", "true")
    monkeypatch.setenv("AE_AUDIT_BACKEND", "memory")
    monkeypatch.setenv("AE_EVENTBUS_BACKEND", "memory")
    monkeypatch.setenv("AE_SANDBOX_BACKEND", "noop")
    reset_settings_cache()
    yield
    reset_settings_cache()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Coordinated Attack Engine" in result.stdout


def test_recon_runs_and_reports_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    result = runner.invoke(app, ["recon", "--scope", str(EXAMPLE_SCOPE), "10.5.0.10"])
    assert result.exit_code == 0, result.stdout
    assert "Engagement engagement-range" in result.stdout
    assert "provider=mock" in result.stdout
    assert "chain_intact" in result.stdout


def test_assess_runs_full_pipeline() -> None:
    result = runner.invoke(app, ["assess", "--scope", str(EXAMPLE_SCOPE), "10.5.0.10"])
    assert result.exit_code == 0, result.stdout
    assert "Verify:" in result.stdout
    assert "Correlate:" in result.stdout
    assert "chain_intact" in result.stdout


def test_engage_runs_full_loop() -> None:
    result = runner.invoke(app, ["engage", "--scope", str(EXAMPLE_SCOPE), "10.5.0.10"])
    assert result.exit_code == 0, result.stdout
    assert "Phases:" in result.stdout
    assert "recon" in result.stdout and "report" in result.stdout
    assert "blue_alerts=" in result.stdout
    assert "chain_intact" in result.stdout


def test_engage_with_objective_plans_kill_chain() -> None:
    result = runner.invoke(
        app,
        ["engage", "--scope", str(EXAMPLE_SCOPE), "10.5.0.10", "--objective", "10.5.0.99:root"],
    )
    assert result.exit_code == 0, result.stdout
    assert "Kill chain to objective" in result.stdout
    assert "Objective 10.5.0.99/root" in result.stdout


def test_recon_missing_scope_file_errors() -> None:
    result = runner.invoke(app, ["recon", "--scope", "/no/such/scope.yaml", "10.5.0.10"])
    assert result.exit_code != 0


def test_help_lists_subcommands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "recon" in result.stdout
    assert "range" in result.stdout
    assert "audit" in result.stdout
