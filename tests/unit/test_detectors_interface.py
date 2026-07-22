"""Unit tests to verify detector interface implementation."""

from gitforensics.detectors import BaseDetector
from gitforensics.models import Confidence, DetectorResult, Evidence, Finding, Severity


class SampleTestDetector(BaseDetector):
    """Sample implementation of BaseDetector for testing interface implementation."""

    def get_rule_id(self) -> str:
        return "GF999"

    def analyze(self, context: object) -> DetectorResult:
        finding = Finding(
            rule_id=self.get_rule_id(),
            title="Sample Test Anomaly",
            description="Sample description for testing detector interface implementation.",
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            evidence=Evidence(data={"test": True}),
        )
        return DetectorResult(rule_id=self.get_rule_id(), findings=[finding])


def test_base_detector_implementation() -> None:
    """Test that custom detectors can subclass BaseDetector correctly."""
    detector = SampleTestDetector()
    assert detector.get_rule_id() == "GF999"

    res = detector.analyze(context=None)
    assert res.rule_id == "GF999"
    assert len(res.findings) == 1
    assert res.findings[0].title == "Sample Test Anomaly"
