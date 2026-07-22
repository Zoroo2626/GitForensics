"""Unit tests for GF009: Tag creation anomalies detector."""

from datetime import datetime

from gitforensics.compat import UTC
from gitforensics.detectors.local.tag_anomalies import TagAnomaliesDetector
from gitforensics.models import Severity, TagNode
from tests.helpers.git_fixtures import make_synthetic_commit, make_synthetic_context


def test_bulk_tags_targeting_single_commit() -> None:
    """Test 5 tags targeting the exact same commit hash."""
    dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    c1 = make_synthetic_commit(commit_hash="h1", committer_date=dt)
    tags = [
        TagNode(
            ref_name=f"refs/tags/v1.{i}",
            short_name=f"v1.{i}",
            target_hash="h1",
            target_type="commit",
            peeled_commit_hash="h1",
            commit_date=dt,
        )
        for i in range(5)
    ]
    context = make_synthetic_context([c1])
    context.history.tags = tags

    detector = TagAnomaliesDetector(same_commit_threshold=5)
    res = detector.analyze(context)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.rule_id == "GF009"
    assert f.severity == Severity.MEDIUM
    assert f.evidence.data["affected_tags_count"] == 5


def test_tagger_date_mismatch_with_commit() -> None:
    """Test tagger date 2 days later than target commit date."""
    c_dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    tagger_dt = datetime(2026, 1, 3, 12, 0, 0, tzinfo=UTC)

    c1 = make_synthetic_commit(commit_hash="h1", committer_date=c_dt)
    t1 = TagNode(
        ref_name="refs/tags/v1.0.0",
        short_name="v1.0.0",
        target_hash="h1",
        target_type="commit",
        tagger_date=tagger_dt,
        commit_date=c_dt,
    )
    context = make_synthetic_context([c1])
    context.history.tags = [t1]

    detector = TagAnomaliesDetector(tagger_tolerance=86400)
    res = detector.analyze(context)
    assert len(res.findings) == 1
    assert res.findings[0].evidence.data["anomaly_type"] == "tagger_date_mismatch"


def test_semver_chronology_conflict() -> None:
    """Test v2.0.0 target commit is dated earlier than v1.0.0 target commit."""
    dt_v1 = datetime(2026, 1, 10, 12, 0, 0, tzinfo=UTC)
    dt_v2 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

    c1 = make_synthetic_commit(commit_hash="h1", committer_date=dt_v1)
    c2 = make_synthetic_commit(commit_hash="h2", committer_date=dt_v2)

    t1 = TagNode(
        ref_name="refs/tags/v1.0.0",
        short_name="v1.0.0",
        target_hash="h1",
        target_type="commit",
        commit_date=dt_v1,
    )
    t2 = TagNode(
        ref_name="refs/tags/v2.0.0",
        short_name="v2.0.0",
        target_hash="h2",
        target_type="commit",
        commit_date=dt_v2,
    )
    context = make_synthetic_context([c1, c2])
    context.history.tags = [t1, t2]

    detector = TagAnomaliesDetector()
    res = detector.analyze(context)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.severity == Severity.HIGH
    assert f.evidence.data["anomaly_type"] == "semver_chronology_conflict"


def test_tagless_repository() -> None:
    """Test repository with no tags returns skipped DetectorResult."""
    context = make_synthetic_context([])
    detector = TagAnomaliesDetector()
    res = detector.analyze(context)
    assert res.skipped
