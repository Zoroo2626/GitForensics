"""Unit tests for transparent risk scoring algorithm and config validation."""

import pytest

from gitforensics.models import Confidence, Evidence, Finding, Severity
from gitforensics.scoring import ScoringConfig, calculate_risk_score, get_assessment_label


def test_scoring_no_findings() -> None:
    """Test score calculation with zero findings produces 0 score and Low observed concern."""
    explanation = calculate_risk_score([])
    assert explanation.score == 0
    assert explanation.assessment_label == "Low observed concern"
    assert explanation.base_score == 0


def test_scoring_info_findings_only() -> None:
    """Test informational findings have 0 weight and produce 0 score."""
    f1 = Finding(
        rule_id="GF007",
        title="Unsigned Commits",
        description="Unsigned commits detected",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        evidence=Evidence({"commits": 5}),
    )
    explanation = calculate_risk_score([f1])
    assert explanation.score == 0
    assert explanation.assessment_label == "Low observed concern"
    assert len(explanation.excluded_findings) == 1


def test_scoring_single_medium_finding() -> None:
    """Test single MEDIUM finding with HIGH confidence produces score 5."""
    f1 = Finding(
        rule_id="GF003",
        title="Commit Burst",
        description="Burst detected",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        evidence=Evidence({"burst": True}),
    )
    explanation = calculate_risk_score([f1])
    assert explanation.score == 5
    assert explanation.assessment_label == "Low observed concern"


def test_scoring_confidence_multipliers() -> None:
    """Test confidence multipliers adjust scores correctly (HIGH=1.0, MEDIUM=0.7, LOW=0.4)."""
    f_high = Finding(
        rule_id="GF006",
        title="Timestamp Anomaly",
        description="Paradox",
        severity=Severity.HIGH,  # Base 15
        confidence=Confidence.HIGH,  # 1.0 -> 15.0
        evidence=Evidence(),
    )
    f_med = Finding(
        rule_id="GF006",
        title="Timestamp Anomaly",
        description="Paradox",
        severity=Severity.HIGH,  # Base 15
        confidence=Confidence.MEDIUM,  # 0.7 -> 10.5
        evidence=Evidence(),
    )
    f_low = Finding(
        rule_id="GF006",
        title="Timestamp Anomaly",
        description="Paradox",
        severity=Severity.HIGH,  # Base 15
        confidence=Confidence.LOW,  # 0.4 -> 6.0
        evidence=Evidence(),
    )

    exp_high = calculate_risk_score([f_high])
    exp_med = calculate_risk_score([f_med])
    exp_low = calculate_risk_score([f_low])

    assert exp_high.score == 15
    assert exp_med.score == 11  # int(round(10.5)) -> 11
    assert exp_low.score == 6


def test_scoring_grouping_caps_regular_intervals_and_bursts() -> None:
    """Test group cap GF002_GF003 limits combined weight at 25 points."""
    f1 = Finding(
        rule_id="GF002",
        title="Regular Intervals",
        description="Exact 60s cadence",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        evidence=Evidence(),
    )
    f2 = Finding(
        rule_id="GF003",
        title="Commit Burst",
        description="Dense burst",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        evidence=Evidence(),
    )

    explanation = calculate_risk_score([f1, f2])
    assert explanation.score == 25
    assert len(explanation.applied_groupings_and_caps) == 1
    assert "GF002_GF003" in explanation.applied_groupings_and_caps[0]


def test_scoring_finding_input_order_independence() -> None:
    """Test finding order does not affect score output or explanation."""
    f1 = Finding("GF001", "Import", "desc", Severity.HIGH, Confidence.HIGH, Evidence())
    f2 = Finding("GF006", "Ordering", "desc", Severity.MEDIUM, Confidence.HIGH, Evidence())

    exp1 = calculate_risk_score([f1, f2])
    exp2 = calculate_risk_score([f2, f1])

    assert exp1.score == exp2.score
    assert exp1.assessment_label == exp2.assessment_label


def test_scoring_upper_boundary_cap_100() -> None:
    """Test score is bounded at maximum 100."""
    findings = [
        Finding(
            f"GF006_idx_{i}",
            "Critical Anomaly",
            "desc",
            Severity.CRITICAL,
            Confidence.HIGH,
            Evidence(),
        )
        for i in range(1, 6)
    ]
    explanation = calculate_risk_score(findings)
    assert explanation.score == 100
    assert explanation.assessment_label == "High observed concern"


def test_scoring_config_validation() -> None:
    """Test invalid scoring configuration values raise ValueError."""
    invalid_config = ScoringConfig(base_weights={Severity.CRITICAL: -10.0})
    with pytest.raises(ValueError):
        invalid_config.validate()


def test_assessment_label_thresholds() -> None:
    """Test exact threshold boundaries for concern labels."""
    assert get_assessment_label(0) == "Low observed concern"
    assert get_assessment_label(15) == "Low observed concern"
    assert get_assessment_label(16) == "Moderate observed concern"
    assert get_assessment_label(35) == "Moderate observed concern"
    assert get_assessment_label(36) == "Elevated observed concern"
    assert get_assessment_label(65) == "Elevated observed concern"
    assert get_assessment_label(66) == "High observed concern"
    assert get_assessment_label(100) == "High observed concern"
