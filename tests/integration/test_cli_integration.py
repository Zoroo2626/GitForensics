"""Integration tests for CLI execution and repository extraction."""

import json
from pathlib import Path

from typer.testing import CliRunner

from gitforensics.cli import app
from tests.helpers.git_fixtures import add_commit, create_dummy_repo

runner = CliRunner()


def test_cli_scan_integration_text_output(tmp_path: Path) -> None:
    """Test full CLI scan command execution with text output on a valid git repository."""
    create_dummy_repo(tmp_path)
    add_commit(tmp_path, message="Integration commit")

    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "text"])
    assert result.exit_code == 0
    assert "Target Extracted:" in result.output or "Target Extracted:" in (
        result.stderr if hasattr(result, "stderr") else ""
    )
    assert "GitForensics Analysis Report" in result.output
    assert "Transparent Risk Score: 0/100" in result.output


def test_cli_scan_integration_json_output(tmp_path: Path) -> None:
    """Test full CLI scan command execution with JSON format."""
    create_dummy_repo(tmp_path)
    add_commit(tmp_path, message="JSON commit")

    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    json_start = result.output.find("{")
    assert json_start != -1
    json_text = result.output[json_start:]
    data = json.loads(json_text)
    assert data["risk_score"] == 0
    assert len(data["findings"]) == 1
    finding = data["findings"][0]
    assert finding["rule_id"] == "GF007"
    assert finding["severity"] == "INFO"
    assert finding["evidence"]["signature_coverage_percentage"] is None
    assert finding["evidence"]["unknown_signature_count"] == 1


def test_cli_scan_integration_file_output(tmp_path: Path) -> None:
    """Test CLI scan command writing output to a file."""
    create_dummy_repo(tmp_path)
    add_commit(tmp_path, message="File output commit")

    output_file = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--format", "json", "--output", str(output_file)],
    )
    assert result.exit_code == 0
    assert output_file.exists()
    data = json.loads(output_file.read_text(encoding="utf-8"))
    assert data["risk_score"] == 0
