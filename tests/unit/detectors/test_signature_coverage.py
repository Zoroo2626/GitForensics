"""Unit tests for GF007: Commit signature coverage detector."""

from gitforensics.detectors.local.signature_coverage import SignatureCoverageDetector
from gitforensics.models import Severity, SignatureStatus
from tests.helpers.git_fixtures import make_synthetic_commit, make_synthetic_context


def test_unsigned_commits_coverage_summary() -> None:
    """Test unsigned commits produce an INFO signature coverage summary."""
    commits = [
        make_synthetic_commit(
            commit_hash=f"h{i}",
            signature_status=SignatureStatus.UNSIGNED,
        )
        for i in range(10)
    ]
    context = make_synthetic_context(commits)

    detector = SignatureCoverageDetector(min_commits=5)
    res = detector.analyze(context)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.rule_id == "GF007"
    assert f.severity == Severity.INFO
    assert f.evidence.data["signature_coverage_percentage"] == 0.0


def test_valid_signatures_coverage_summary() -> None:
    """Test 100% valid signed commits produce INFO signature coverage summary."""
    commits = [
        make_synthetic_commit(
            commit_hash=f"h{i}",
            signature_status=SignatureStatus.VALID,
        )
        for i in range(5)
    ]
    context = make_synthetic_context(commits)

    detector = SignatureCoverageDetector(min_commits=5)
    res = detector.analyze(context)
    assert len(res.findings) == 1
    assert res.findings[0].evidence.data["signature_coverage_percentage"] == 100.0


def test_invalid_and_revoked_signatures() -> None:
    """Test bad and revoked signatures produce a HIGH severity finding."""
    c_valid = [
        make_synthetic_commit(commit_hash=f"hv{i}", signature_status=SignatureStatus.VALID)
        for i in range(5)
    ]
    c_bad = [
        make_synthetic_commit(commit_hash="hbad1", signature_status=SignatureStatus.BAD),
        make_synthetic_commit(commit_hash="hrev1", signature_status=SignatureStatus.REVOKED_KEY),
    ]
    context = make_synthetic_context(c_valid + c_bad)

    detector = SignatureCoverageDetector(min_commits=5)
    res = detector.analyze(context)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.severity == Severity.HIGH
    assert f.evidence.data["invalid_signature_count"] == 2
