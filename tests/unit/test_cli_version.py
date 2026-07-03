"""Unit tests for the version command."""

from typer.testing import CliRunner

from bqcheck.cli import app

runner = CliRunner()


def test_version_command_displays_cli_version():
    """The version command prints the installed CLI version."""
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "bqcheck 0.1.0" in result.stdout


def test_version_command_verbose_displays_debug_context(monkeypatch):
    """Verbose version output includes useful support/debug details."""
    monkeypatch.setenv("BQCHECK_API_URL", "https://api.example.test")
    monkeypatch.setenv("BQCHECK_REAL_MODE", "false")
    monkeypatch.setenv("BQCHECK_REAL_SCAN", "false")
    monkeypatch.setenv("BQCHECK_SUPPORT_URL", "https://support.example.test")

    result = runner.invoke(app, ["version", "--verbose"])

    assert result.exit_code == 0
    assert "bqcheck 0.1.0" in result.stdout
    assert "API URL: https://api.example.test" in result.stdout
    assert "BQCHECK_REAL_MODE: false" in result.stdout
    assert "BQCHECK_REAL_SCAN: false" in result.stdout
    assert "Support URL: https://support.example.test" in result.stdout
