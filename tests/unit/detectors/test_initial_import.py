"""Unit tests for GF001: Initial import concentration detector."""

from gitforensics.detectors.local.initial_import import InitialImportDetector
from gitforensics.models import Severity
from tests.helpers.git_fixtures import make_synthetic_commit, make_synthetic_context


def test_initial_import_below_threshold() -> None:
    """Test no finding when root commit concentration is below threshold (50%)."""
    c1 = make_synthetic_commit(commit_hash="h1", changed_files_count=5, insertions=50)
    c2 = make_synthetic_commit(commit_hash="h2", changed_files_count=3, insertions=30)
    c3 = make_synthetic_commit(commit_hash="h3", changed_files_count=2, insertions=20)
    context = make_synthetic_context([c1, c2, c3])

    detector = InitialImportDetector(threshold_percent=80.0)
    res = detector.analyze(context)
    assert len(res.findings) == 0


def test_initial_import_at_threshold() -> None:
    """Test finding produced at threshold (80% concentration)."""
    c1 = make_synthetic_commit(commit_hash="h1", changed_files_count=8, insertions=80)
    c2 = make_synthetic_commit(commit_hash="h2", changed_files_count=1, insertions=10)
    c3 = make_synthetic_commit(commit_hash="h3", changed_files_count=1, insertions=10)
    context = make_synthetic_context([c1, c2, c3])

    detector = InitialImportDetector(threshold_percent=80.0)
    res = detector.analyze(context)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.rule_id == "GF001"
    assert f.severity == Severity.MEDIUM
    assert f.evidence.data["calculated_percentage"] == 80.0


def test_initial_import_above_threshold_high_severity() -> None:
    """Test HIGH severity when concentration is >= 95%."""
    c1 = make_synthetic_commit(commit_hash="h1", changed_files_count=96, insertions=960)
    c2 = make_synthetic_commit(commit_hash="h2", changed_files_count=2, insertions=20)
    c3 = make_synthetic_commit(commit_hash="h3", changed_files_count=2, insertions=20)
    context = make_synthetic_context([c1, c2, c3])

    detector = InitialImportDetector(threshold_percent=80.0)
    res = detector.analyze(context)
    assert len(res.findings) == 1
    assert res.findings[0].severity == Severity.HIGH


def test_initial_import_tiny_repository_skipped() -> None:
    """Test that tiny repositories (< 3 commits) are skipped."""
    c1 = make_synthetic_commit(commit_hash="h1", changed_files_count=100)
    context = make_synthetic_context([c1])

    detector = InitialImportDetector(min_commits=3)
    res = detector.analyze(context)
    assert res.skipped
    assert len(res.findings) == 0


def test_initial_import_empty_repository() -> None:
    """Test empty repository handling."""
    context = make_synthetic_context([])
    detector = InitialImportDetector()
    res = detector.analyze(context)
    assert res.skipped
