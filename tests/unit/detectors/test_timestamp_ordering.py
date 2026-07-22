"""Unit tests for GF006: Timestamp ordering anomalies detector."""

from datetime import datetime, timedelta

from gitforensics.compat import UTC
from gitforensics.detectors.local.timestamp_ordering import TimestampOrderingDetector
from gitforensics.models import Severity
from tests.helpers.git_fixtures import make_synthetic_commit, make_synthetic_context


def test_author_timestamp_after_committer_timestamp() -> None:
    """Test author timestamp 10 minutes later than committer timestamp."""
    base_dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    c = make_synthetic_commit(
        commit_hash="h1",
        author_date=base_dt + timedelta(minutes=10),
        committer_date=base_dt,
    )
    context = make_synthetic_context([c])

    detector = TimestampOrderingDetector(author_after_tolerance=60)
    res = detector.analyze(context)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.rule_id == "GF006"
    assert f.severity == Severity.MEDIUM
    assert f.evidence.data["anomaly_type"] == "author_after_committer"


def test_child_commit_predates_parent_commit() -> None:
    """Test child commit timestamped earlier than parent commit."""
    parent_dt = datetime(2026, 1, 2, 12, 0, 0, tzinfo=UTC)
    child_dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

    p = make_synthetic_commit(commit_hash="p1", committer_date=parent_dt)
    c = make_synthetic_commit(commit_hash="c1", parents=["p1"], committer_date=child_dt)
    context = make_synthetic_context([p, c])

    detector = TimestampOrderingDetector(child_predates_tolerance=60)
    res = detector.analyze(context)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.severity == Severity.HIGH
    assert f.evidence.data["anomaly_type"] == "child_predates_parent"


def test_future_dated_commits_with_injectable_clock() -> None:
    """Test future dated commit using explicit injectable analysis_clock."""
    clock = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    future_dt = datetime(2026, 1, 5, 12, 0, 0, tzinfo=UTC)

    c = make_synthetic_commit(commit_hash="h_future", committer_date=future_dt)
    context = make_synthetic_context([c])

    detector = TimestampOrderingDetector(analysis_clock=clock, future_tolerance=86400)
    res = detector.analyze(context)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.severity == Severity.HIGH
    assert f.evidence.data["anomaly_type"] == "future_commit"


def test_normal_timestamps_no_finding() -> None:
    """Test normal chronologically ordered commits yield no finding."""
    t1 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    t2 = datetime(2026, 1, 1, 11, 0, 0, tzinfo=UTC)
    clock = datetime(2026, 1, 2, 12, 0, 0, tzinfo=UTC)

    p = make_synthetic_commit(commit_hash="p1", committer_date=t1, author_date=t1)
    c = make_synthetic_commit(commit_hash="c1", parents=["p1"], committer_date=t2, author_date=t2)
    context = make_synthetic_context([p, c])

    detector = TimestampOrderingDetector(analysis_clock=clock)
    res = detector.analyze(context)
    assert len(res.findings) == 0
