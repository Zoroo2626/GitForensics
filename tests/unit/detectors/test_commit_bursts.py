"""Unit tests for GF003: Unusual commit bursts detector."""

from datetime import datetime, timedelta

from gitforensics.compat import UTC
from gitforensics.detectors.local.commit_bursts import CommitBurstsDetector
from gitforensics.models import Severity
from tests.helpers.git_fixtures import make_synthetic_commit, make_synthetic_context


def test_dense_commit_burst() -> None:
    """Test detection of an unusually dense burst (15 commits in 5 mins)."""
    base_dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    commits = [
        make_synthetic_commit(
            commit_hash=f"h{i}",
            author_date=base_dt + timedelta(seconds=i * 10),
        )
        for i in range(15)
    ]
    context = make_synthetic_context(commits)

    detector = CommitBurstsDetector(min_commits=10, rate_threshold=2.0)
    res = detector.analyze(context)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.rule_id == "GF003"
    assert f.severity in (Severity.MEDIUM, Severity.HIGH)
    assert f.evidence.data["commit_count_in_window"] == 15


def test_normal_short_work_session_no_finding() -> None:
    """Test normal short work session (3 commits in 5 mins) yields no finding."""
    base_dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    commits = [
        make_synthetic_commit(
            commit_hash=f"h{i}",
            author_date=base_dt + timedelta(minutes=i * 2),
        )
        for i in range(3)
    ]
    context = make_synthetic_context(commits)

    detector = CommitBurstsDetector(min_commits=10)
    res = detector.analyze(context)
    assert res.skipped or len(res.findings) == 0


def test_burst_boundary_at_threshold() -> None:
    """Test boundary condition exactly at min_commits (10 commits in 5 mins)."""
    base_dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    commits = [
        make_synthetic_commit(
            commit_hash=f"h{i}",
            author_date=base_dt + timedelta(seconds=i * 20),
        )
        for i in range(10)
    ]
    context = make_synthetic_context(commits)

    detector = CommitBurstsDetector(min_commits=10, rate_threshold=2.0)
    res = detector.analyze(context)
    assert len(res.findings) == 1
    assert res.findings[0].evidence.data["commit_count_in_window"] == 10
