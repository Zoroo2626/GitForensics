"""Unit tests for GF004: Contributor concentration detector."""

from gitforensics.detectors.local.contributor_concentration import (
    ContributorConcentrationDetector,
)
from gitforensics.models import Severity
from tests.helpers.git_fixtures import make_synthetic_commit, make_synthetic_context


def test_single_contributor_repository_info_finding() -> None:
    """Test single contributor repository produces INFO severity finding."""
    commits = [
        make_synthetic_commit(
            commit_hash=f"h{i}",
            author_email="single@example.com",
            author_name="Single Author",
        )
        for i in range(10)
    ]
    context = make_synthetic_context(commits)

    detector = ContributorConcentrationDetector(min_commits=5)
    res = detector.analyze(context)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.rule_id == "GF004"
    assert f.severity == Severity.INFO
    assert f.evidence.data["total_contributor_identities"] == 1


def test_balanced_contributor_repository_no_finding() -> None:
    """Test balanced multi-contributor repo (50/50) produces no finding."""
    c1 = [
        make_synthetic_commit(commit_hash=f"ha{i}", author_email="alice@example.com")
        for i in range(5)
    ]
    c2 = [
        make_synthetic_commit(commit_hash=f"hb{i}", author_email="bob@example.com")
        for i in range(5)
    ]
    context = make_synthetic_context(c1 + c2)

    detector = ContributorConcentrationDetector(min_commits=5, threshold_percent=90.0)
    res = detector.analyze(context)
    assert len(res.findings) == 0


def test_dominant_contributor_repository() -> None:
    """Test dominant contributor (95%) produces finding."""
    c1 = [
        make_synthetic_commit(commit_hash=f"ha{i}", author_email="alice@example.com")
        for i in range(19)
    ]
    c2 = [make_synthetic_commit(commit_hash="hb0", author_email="bob@example.com")]
    context = make_synthetic_context(c1 + c2)

    detector = ContributorConcentrationDetector(min_commits=5, threshold_percent=90.0)
    res = detector.analyze(context)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.evidence.data["highest_contributor_percentage"] == 95.0


def test_case_differences_normalized() -> None:
    """Test that email case differences are normalized."""
    c1 = [
        make_synthetic_commit(commit_hash=f"ha{i}", author_email="Alice@Example.COM")
        for i in range(5)
    ]
    c2 = [
        make_synthetic_commit(commit_hash=f"hb{i}", author_email="alice@example.com")
        for i in range(5)
    ]
    context = make_synthetic_context(c1 + c2)

    detector = ContributorConcentrationDetector(min_commits=5)
    res = detector.analyze(context)
    assert len(res.findings) == 1
    assert res.findings[0].evidence.data["total_contributor_identities"] == 1
