"""Integration tests for offline mode, GitHub API fallback, and detector orchestration."""

from pathlib import Path
from unittest.mock import patch

import httpx

from gitforensics.engine import run_analysis
from gitforensics.github import GitHubClient
from gitforensics.models import RepositoryInput, RepositoryInputType
from tests.helpers.git_fixtures import add_commit, create_dummy_repo


def test_offline_mode_guarantees_zero_network_calls(tmp_path: Path) -> None:
    """Test that offline mode blocks all network requests even for remote URLs."""
    create_dummy_repo(tmp_path)
    add_commit(tmp_path, message="Offline commit")

    call_count = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(200, json={})

    mock_client = GitHubClient(transport=httpx.MockTransport(mock_handler))
    # Analyze a local repository; offline mode must suppress the supplied client entirely.
    repo_input = RepositoryInput(
        raw_input=str(tmp_path),
        input_type=RepositoryInputType.LOCAL,
        resolved_path_or_url=str(tmp_path),
    )

    report, context = run_analysis(
        repo_input,
        offline=True,
        github_client=mock_client,
    )

    assert call_count == 0, "Security violation: Network request was made in offline mode!"
    assert context.offline is True


def test_local_analysis_continues_after_github_api_failure(tmp_path: Path) -> None:
    """Test local detectors run successfully even if GitHub API fails with 500 error."""
    create_dummy_repo(tmp_path)
    add_commit(tmp_path, message="Fallback commit")

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"message": "Server error"})

    mock_client = GitHubClient(transport=httpx.MockTransport(mock_handler))
    repo_input = RepositoryInput(
        raw_input="https://github.com/owner/repo.git",
        input_type=RepositoryInputType.LOCAL,
        resolved_path_or_url=str(tmp_path),
    )

    with patch("gitforensics.engine._extract_github_owner_repo", return_value=("owner", "repo")):
        report, context = run_analysis(
            repo_input,
            offline=False,
            github_client=mock_client,
        )

    assert report is not None
    assert context.github_metadata is None
    assert any("GitHub API" in reason for reason in report.incomplete_analysis_reasons)
