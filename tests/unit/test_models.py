"""Unit tests for models, enums, construction, scoring, and github client."""

from gitforensics.github import GitHubClient
from gitforensics.models import (
    AnalysisReport,
    Confidence,
    DetectorResult,
    Evidence,
    Finding,
    OutputFormat,
    RepositoryInput,
    RepositoryInputType,
    RiskScore,
    Severity,
)
from gitforensics.scoring import calculate_risk_score


def test_enum_values_and_strings() -> None:
    """Test Enum values and stable string representations."""
    assert Severity.INFO.value == "INFO"
    assert Severity.LOW.value == "LOW"
    assert Severity.MEDIUM.value == "MEDIUM"
    assert Severity.HIGH.value == "HIGH"
    assert Severity.CRITICAL.value == "CRITICAL"

    assert Confidence.LOW.value == "LOW"
    assert Confidence.MEDIUM.value == "MEDIUM"
    assert Confidence.HIGH.value == "HIGH"

    assert OutputFormat.TEXT.value == "text"
    assert OutputFormat.JSON.value == "json"

    assert RepositoryInputType.LOCAL.value == "local"
    assert RepositoryInputType.REMOTE.value == "remote"


def test_model_construction() -> None:
    """Test building dataclass models."""
    repo_input = RepositoryInput(
        raw_input="https://github.com/org/repo",
        input_type=RepositoryInputType.REMOTE,
        resolved_path_or_url="https://github.com/org/repo",
    )
    assert repo_input.raw_input == "https://github.com/org/repo"
    assert repo_input.input_type == RepositoryInputType.REMOTE

    evidence = Evidence(data={"commit": "abc1234", "count": 42})
    finding = Finding(
        rule_id="GF001",
        title="Initial Import Concentration",
        description="Massive initial commit",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        evidence=evidence,
    )
    assert finding.rule_id == "GF001"
    assert finding.severity == Severity.HIGH
    assert finding.evidence.data["commit"] == "abc1234"

    score = RiskScore(score=15, base_score=15, formula="test_formula")
    assert score.score == 15

    result = DetectorResult(rule_id="GF001", findings=[finding])
    assert len(result.findings) == 1
    assert not result.skipped


def test_report_serialization() -> None:
    """Test AnalysisReport to_dict serialization."""
    evidence = Evidence(data={"key": "val"})
    finding = Finding(
        rule_id="GF006",
        title="Timestamp Ordering Anomaly",
        description="Parent timestamp predates child",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        evidence=evidence,
    )
    report = AnalysisReport(
        repository="/path/to/repo",
        risk_score=30,
        scoring_breakdown={"base": 30},
        findings=[finding],
    )

    data = report.to_dict()
    assert data["repository"] == "/path/to/repo"
    assert data["risk_score"] == 30
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "GF006"
    assert data["findings"][0]["severity"] == "CRITICAL"
    assert data["findings"][0]["confidence"] == "HIGH"
    assert data["findings"][0]["evidence"]["key"] == "val"


def test_github_client_authentication() -> None:
    """Test GitHubClient authentication state."""
    client_unauth = GitHubClient()
    assert not client_unauth.is_authenticated()

    client_auth = GitHubClient(token="test-token")
    assert client_auth.is_authenticated()


def test_calculate_risk_score_with_findings() -> None:
    """Test calculate_risk_score with a variety of severities."""
    findings = [
        Finding(
            rule_id="GF001",
            title="Critical Anomaly",
            description="desc",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            evidence=Evidence(),
        ),
        Finding(
            rule_id="GF002",
            title="High Anomaly",
            description="desc",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence=Evidence(),
        ),
        Finding(
            rule_id="GF003",
            title="Medium Anomaly",
            description="desc",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            evidence=Evidence(),
        ),
        Finding(
            rule_id="GF004",
            title="Low Anomaly",
            description="desc",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            evidence=Evidence(),
        ),
    ]

    # 30 + 15 + 5 + 1 = 51
    risk = calculate_risk_score(findings)
    assert risk.score == 51
    assert risk.base_score == 51
    assert "4 finding(s)" in risk.details
