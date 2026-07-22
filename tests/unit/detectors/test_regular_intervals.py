"""Unit tests for GF002: Mechanically regular commit intervals detector."""

from datetime import datetime, timedelta

from gitforensics.compat import UTC
from gitforensics.detectors.local.regular_intervals import RegularIntervalsDetector
from tests.helpers.git_fixtures import make_synthetic_commit, make_synthetic_context


def test_regular_60_second_intervals() -> None:
    """Test detection of exact 60-second commit intervals."""
    base_dt = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    commits = [
        make_synthetic_commit(
            commit_hash=f"h{i}",
            author_date=base_dt + timedelta(seconds=60 * i),
            committer_date=base_dt + timedelta(seconds=60 * i),
        )
        for i in range(10)
    ]
    context = make_synthetic_context(commits)

    detector = RegularIntervalsDetector(match_threshold=50.0)
    res = detector.analyze(context)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.rule_id == "GF002"
    assert f.evidence.data["dominant_interval_seconds"] == 60
    assert f.evidence.data["matching_percentage"] == 100.0


def test_near_regular_intervals_inside_tolerance() -> None:
    """Test intervals with slight jitter within 2s tolerance."""
    base_dt = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    offsets = [0, 60, 121, 180, 241, 300, 360, 421]
    commits = [
        make_synthetic_commit(
            commit_hash=f"h{i}",
            author_date=base_dt + timedelta(seconds=offsets[i]),
        )
        for i in range(len(offsets))
    ]
    context = make_synthetic_context(commits)

    detector = RegularIntervalsDetector(tolerance=2, match_threshold=50.0)
    res = detector.analyze(context)
    assert len(res.findings) == 1
    assert res.findings[0].evidence.data["matching_percentage"] >= 50.0


def test_intervals_outside_tolerance_no_finding() -> None:
    """Test irregular intervals exceeding tolerance produce no finding."""
    base_dt = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    offsets = [0, 10, 150, 400, 420, 1000, 1200]
    commits = [
        make_synthetic_commit(
            commit_hash=f"h{i}",
            author_date=base_dt + timedelta(seconds=offsets[i]),
        )
        for i in range(len(offsets))
    ]
    context = make_synthetic_context(commits)

    detector = RegularIntervalsDetector(match_threshold=50.0)
    res = detector.analyze(context)
    assert len(res.findings) == 0


def test_normal_irregular_human_commit_patterns() -> None:
    """Test human commit patterns produce no finding."""
    base_dt = datetime(2026, 1, 1, 9, 0, 0, tzinfo=UTC)
    # Human commits scattered over hours/days
    offsets = [0, 345, 1890, 7200, 14400, 86400, 90000, 95000]
    commits = [
        make_synthetic_commit(
            commit_hash=f"h{i}",
            author_date=base_dt + timedelta(seconds=offsets[i]),
        )
        for i in range(len(offsets))
    ]
    context = make_synthetic_context(commits)

    detector = RegularIntervalsDetector()
    res = detector.analyze(context)
    assert len(res.findings) == 0


def test_merge_commits_ignored() -> None:
    """Test that merge commits are excluded from interval analysis."""
    base_dt = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    commits = [
        make_synthetic_commit(commit_hash="h0", author_date=base_dt),
        make_synthetic_commit(commit_hash="h1", author_date=base_dt + timedelta(seconds=60)),
        make_synthetic_commit(
            commit_hash="m1",
            parents=["h0", "h1"],
            author_date=base_dt + timedelta(seconds=65),
        ),  # merge commit
        make_synthetic_commit(commit_hash="h2", author_date=base_dt + timedelta(seconds=120)),
        make_synthetic_commit(commit_hash="h3", author_date=base_dt + timedelta(seconds=180)),
        make_synthetic_commit(commit_hash="h4", author_date=base_dt + timedelta(seconds=240)),
        make_synthetic_commit(commit_hash="h5", author_date=base_dt + timedelta(seconds=300)),
    ]
    context = make_synthetic_context(commits)

    detector = RegularIntervalsDetector()
    res = detector.analyze(context)
    assert len(res.findings) == 1
    assert res.findings[0].evidence.data["dominant_interval_seconds"] == 60


def test_unsorted_input_commits_handled() -> None:
    """Test that input commits in arbitrary order are sorted correctly before calculation."""
    base_dt = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    c0 = make_synthetic_commit(commit_hash="h0", author_date=base_dt)
    c1 = make_synthetic_commit(commit_hash="h1", author_date=base_dt + timedelta(seconds=60))
    c2 = make_synthetic_commit(commit_hash="h2", author_date=base_dt + timedelta(seconds=120))
    c3 = make_synthetic_commit(commit_hash="h3", author_date=base_dt + timedelta(seconds=180))
    c4 = make_synthetic_commit(commit_hash="h4", author_date=base_dt + timedelta(seconds=240))
    c5 = make_synthetic_commit(commit_hash="h5", author_date=base_dt + timedelta(seconds=300))

    # Pass in shuffled order
    context = make_synthetic_context([c4, c0, c5, c2, c1, c3])

    detector = RegularIntervalsDetector()
    res = detector.analyze(context)
    assert len(res.findings) == 1
