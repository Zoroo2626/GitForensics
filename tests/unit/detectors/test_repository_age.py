"""Unit tests for GF010: Repository age compared with history detector."""

from datetime import datetime

from gitforensics.compat import UTC
from gitforensics.detectors.remote.repository_age import RepositoryAgeDetector
from gitforensics.models import GitHubMetadata, Severity
from tests.helpers.git_fixtures import make_synthetic_commit, make_synthetic_context


def test_repository_age_imported_history() -> None:
    """Test 100% imported history predating GitHub creation produces MEDIUM finding."""
    repo_created = datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC)
    old_dt = datetime(2020, 1, 1, 0, 0, 0, tzinfo=UTC)

    commits = [make_synthetic_commit(commit_hash=f"h{i}", committer_date=old_dt) for i in range(10)]
    context = make_synthetic_context(commits)
    context.github_metadata = GitHubMetadata(
        owner="org",
        name="repo",
        repo_id=123,
        created_at=repo_created,
        updated_at=repo_created,
        pushed_at=repo_created,
        default_branch="main",
        visibility="public",
        archived=False,
        disabled=False,
        is_fork=False,
    )

    detector = RepositoryAgeDetector()
    res = detector.analyze(context)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.rule_id == "GF010"
    assert f.severity == Severity.MEDIUM
    assert f.evidence.data["commits_predating_creation_percentage"] == 100.0


def test_repository_age_fork_history_info() -> None:
    """Test fork repository history predating creation produces INFO finding."""
    repo_created = datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC)
    old_dt = datetime(2020, 1, 1, 0, 0, 0, tzinfo=UTC)

    commits = [make_synthetic_commit(commit_hash=f"h{i}", committer_date=old_dt) for i in range(10)]
    context = make_synthetic_context(commits)
    context.github_metadata = GitHubMetadata(
        owner="user",
        name="forked-repo",
        repo_id=456,
        created_at=repo_created,
        updated_at=repo_created,
        pushed_at=repo_created,
        default_branch="main",
        visibility="public",
        archived=False,
        disabled=False,
        is_fork=True,
        parent_owner="original_org",
        parent_name="upstream",
    )

    detector = RepositoryAgeDetector()
    res = detector.analyze(context)
    assert len(res.findings) == 1
    assert res.findings[0].severity == Severity.INFO


def test_repository_age_missing_metadata_skipped() -> None:
    """Test detector skipped when GitHub metadata is missing or offline mode enabled."""
    context = make_synthetic_context([])
    detector = RepositoryAgeDetector()
    res = detector.analyze(context)
    assert res.skipped
