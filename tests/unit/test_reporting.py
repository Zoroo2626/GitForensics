"""Unit tests for reporting structure and rendering."""

import json

from gitforensics.models import (
    AnalysisReport,
    Confidence,
    Evidence,
    Finding,
    OutputFormat,
    Severity,
)
from gitforensics.reporting import render_report


def test_empty_report_text() -> None:
    """Test empty report rendering in text format."""
    report = AnalysisReport(repository="/dummy/repo", risk_score=0)
    rendered = render_report(report, output_format=OutputFormat.TEXT)

    assert "GitForensics Analysis Report" in rendered
    assert "Repository: /dummy/repo" in rendered
    assert "Transparent Risk Score: 0/100" in rendered
    assert "No findings reported." in rendered
    assert "Disclaimer" in rendered


def test_empty_report_json() -> None:
    """Test empty report rendering in JSON format."""
    report = AnalysisReport(repository="https://github.com/dummy/repo", risk_score=0)
    rendered = render_report(report, output_format=OutputFormat.JSON)

    data = json.loads(rendered)
    assert data["repository"] == "https://github.com/dummy/repo"
    assert data["risk_score"] == 0
    assert data["findings"] == []


def test_report_with_findings_rendering() -> None:
    """Test rendering report containing findings."""
    finding = Finding(
        rule_id="GF002",
        title="Regular Commit Intervals",
        description="Mechanically uniform commit cadence detected",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        evidence=Evidence(data={"interval_seconds": 60}),
    )
    report = AnalysisReport(
        repository="/test/repo",
        risk_score=5,
        scoring_breakdown={"formula": "Score = MIN(100, ...)"},
        findings=[finding],
    )
    rendered_text = render_report(report, output_format=OutputFormat.TEXT)
    assert "GF002" in rendered_text
    assert "MEDIUM" in rendered_text
    assert "Findings Summary" in rendered_text
