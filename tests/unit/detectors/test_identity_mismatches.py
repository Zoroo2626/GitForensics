"""Unit tests for GF005: Author and committer identity mismatches detector."""

from gitforensics.detectors.local.identity_mismatches import IdentityMismatchesDetector
from gitforensics.models import Severity
from tests.helpers.git_fixtures import make_synthetic_commit, make_synthetic_context


def test_isolated_identity_mismatch_below_threshold() -> None:
    """Test isolated identity mismatch (1 out of 10) produces no finding below 20% threshold."""
    c_matching = [
        make_synthetic_commit(
            commit_hash=f"hm{i}",
            author_email="user@example.com",
            committer_email="user@example.com",
        )
        for i in range(9)
    ]
    c_mismatch = [
        make_synthetic_commit(
            commit_hash="hbad0",
            author_email="author@example.com",
            committer_email="committer@example.com",
        )
    ]
    context = make_synthetic_context(c_matching + c_mismatch)

    detector = IdentityMismatchesDetector(min_mismatches=3, min_percentage=20.0)
    res = detector.analyze(context)
    assert len(res.findings) == 0


def test_systematic_identity_mismatches() -> None:
    """Test systematic identity mismatches (100%) produce finding."""
    commits = [
        make_synthetic_commit(
            commit_hash=f"h{i}",
            author_email=f"author{i}@example.com",
            committer_email="rewriter@example.com",
        )
        for i in range(5)
    ]
    context = make_synthetic_context(commits)

    detector = IdentityMismatchesDetector(min_mismatches=3, min_percentage=20.0)
    res = detector.analyze(context)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.rule_id == "GF005"
    assert f.severity == Severity.MEDIUM
    assert f.evidence.data["mismatch_percentage"] == 100.0
