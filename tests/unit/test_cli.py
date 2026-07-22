"""Unit tests for CLI commands and argument validation."""

from typer.testing import CliRunner

from gitforensics.cli import app

runner = CliRunner()
HELP_ENV = {"COLUMNS": "160", "NO_COLOR": "1"}


def test_cli_help() -> None:
    """Test gitforensics --help output."""
    result = runner.invoke(app, ["--help"], env=HELP_ENV)
    assert result.exit_code == 0
    assert "GitForensics" in result.output
    assert "scan" in result.output


def test_cli_version() -> None:
    """Test gitforensics --version output."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "gitforensics version 0.1.0" in result.output


def test_scan_help() -> None:
    """Test gitforensics scan --help output."""
    result = runner.invoke(app, ["scan", "--help"], env=HELP_ENV)
    assert result.exit_code == 0
    assert "Scan a repository" in result.output


def test_scan_missing_argument() -> None:
    """Test scan command without required argument."""
    result = runner.invoke(app, ["scan"])
    assert result.exit_code != 0
    assert "Missing argument" in result.output or "Error" in result.output


def test_scan_invalid_local_path() -> None:
    """Test scan command with non-existent local directory path."""
    result = runner.invoke(app, ["scan", "/non/existent/path/to/repo"])
    assert result.exit_code == 3
    assert "Error" in result.output
