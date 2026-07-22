"""Unit tests for terminal and JSON report formatting and file writing."""

import json
from pathlib import Path

import pytest

from gitforensics.errors import CLIArgumentError, OutputWriteError
from gitforensics.models import (
    AnalysisReport,
    Confidence,
    Evidence,
    Finding,
    OutputFormat,
    Severity,
    sanitize_path_str,
)
from gitforensics.reporting import render_report, write_report_to_file


def test_sanitize_path_str_removes_temporary_clone_directories() -> None:
    """Test temporary clone directory paths are sanitized into clean placeholders."""
    raw_linux = "/tmp/gitforensics_clone_ab12cd/src/main.py"
    raw_win = r"C:\Temp\gitforensics_clone_xy99\lib.py"

    clean_linux = sanitize_path_str(raw_linux)
    clean_win = sanitize_path_str(raw_win)

    assert "/tmp/gitforensics_clone_" not in clean_linux
    assert "<REMOTE_REPOSITORY>/" in clean_linux
    assert "gitforensics_clone_" not in clean_win


def test_render_report_terminal_text_and_no_color() -> None:
    """Test rendering report in terminal text format with and without color."""
    f1 = Finding(
        "GF001",
        "Initial Import",
        "Large import",
        Severity.HIGH,
        Confidence.HIGH,
        Evidence({"files": 500}),
    )
    report = AnalysisReport(
        repository="test/repo",
        risk_score=15,
        assessment_label="Low observed concern",
        findings=[f1],
    )

    rendered_color = render_report(report, output_format=OutputFormat.TERMINAL, no_color=False)
    rendered_nocolor = render_report(report, output_format=OutputFormat.TERMINAL, no_color=True)

    assert "GitForensics Analysis Report" in rendered_color
    assert "Low observed concern" in rendered_color
    assert "GF001" in rendered_color
    assert "GitForensics Analysis Report" in rendered_nocolor


def test_render_report_quiet_mode() -> None:
    """Test quiet mode renders only essential assessment and summary."""
    f1 = Finding(
        "GF006",
        "Timestamp Paradox",
        "Child predates parent",
        Severity.HIGH,
        Confidence.HIGH,
        Evidence(),
    )
    report = AnalysisReport(
        repository="test/repo",
        risk_score=40,
        assessment_label="Elevated observed concern",
        findings=[f1],
    )

    rendered_quiet = render_report(report, output_format=OutputFormat.TERMINAL, quiet=True)
    assert "Elevated observed concern" in rendered_quiet
    assert "40/100" in rendered_quiet
    assert "Detected Anomalies" not in rendered_quiet


def test_render_report_json_format_deterministic_keys() -> None:
    """Test JSON report output is valid UTF-8 and contains schema_version and risk_score."""
    f1 = Finding(
        "GF003",
        "Commit Burst",
        "15 commits in 5m",
        Severity.MEDIUM,
        Confidence.HIGH,
        Evidence({"count": 15}),
    )
    report = AnalysisReport(
        repository="owner/repo",
        risk_score=25,
        assessment_label="Moderate observed concern",
        findings=[f1],
    )

    json_str = render_report(report, output_format=OutputFormat.JSON)
    data = json.loads(json_str)

    assert data["schema_version"] == "1.0.0"
    assert data["repository"] == "owner/repo"
    assert data["risk_score"] == 25
    assert data["assessment_label"] == "Moderate observed concern"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "GF003"


def test_write_report_to_file_existing_file_rejection_and_force(tmp_path: Path) -> None:
    """Test writing report fails if file exists without --force, and succeeds with --force."""
    output_file = tmp_path / "report.json"
    output_file.write_text("existing content", encoding="utf-8")

    with pytest.raises(CLIArgumentError) as exc_info:
        write_report_to_file("new content", str(output_file), force=False)
    assert "already exists" in str(exc_info.value)

    write_report_to_file("new content", str(output_file), force=True)
    assert output_file.read_text(encoding="utf-8") == "new content"


def test_write_report_to_file_non_existent_parent_directory(tmp_path: Path) -> None:
    """Test writing report fails if parent directory does not exist."""
    bad_path = tmp_path / "non_existent_dir" / "report.json"
    with pytest.raises(OutputWriteError):
        write_report_to_file("content", str(bad_path), force=False)
