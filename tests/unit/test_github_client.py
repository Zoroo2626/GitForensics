"""Unit tests for GitHub REST API client using HTTPX MockTransport."""

from datetime import datetime

import httpx
import pytest

from gitforensics.compat import UTC
from gitforensics.errors import (
    GitHubAuthError,
    GitHubNotFoundError,
    GitHubRateLimitError,
)
from gitforensics.github import GitHubClient


def test_github_client_unauthenticated_metadata() -> None:
    """Test successful public repository metadata retrieval."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Accept"] == "application/vnd.github+json"
        assert request.headers["X-GitHub-Api-Version"] == "2022-11-28"
        assert "Authorization" not in request.headers
        json_body = {
            "owner": {"login": "octocat"},
            "name": "Hello-World",
            "id": 129482,
            "created_at": "2020-01-01T00:00:00Z",
            "updated_at": "2020-01-02T00:00:00Z",
            "pushed_at": "2020-01-03T00:00:00Z",
            "default_branch": "main",
            "visibility": "public",
            "archived": False,
            "disabled": False,
            "fork": False,
            "size": 100,
            "open_issues_count": 5,
            "stargazers_count": 42,
            "forks_count": 10,
            "watchers_count": 42,
            "language": "Python",
            "license": {"spdx_id": "MIT"},
            "topics": ["security", "git"],
        }
        return httpx.Response(200, json=json_body)

    client = GitHubClient(transport=httpx.MockTransport(mock_handler))
    meta = client.get_repository_metadata("octocat", "Hello-World")

    assert meta.owner == "octocat"
    assert meta.name == "Hello-World"
    assert meta.repo_id == 129482
    assert meta.created_at == datetime(2020, 1, 1, 0, 0, 0, tzinfo=UTC)
    assert meta.language == "Python"
    assert meta.license == "MIT"
    assert not meta.is_fork


def test_github_client_token_authentication_headers() -> None:
    """Test that Authorization header is injected and token is not exposed."""
    secret_token = "test-secret-token-12345"

    def mock_handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == f"Bearer {secret_token}"
        return httpx.Response(200, json={"owner": {"login": "o"}, "name": "r"})

    client = GitHubClient(token=secret_token, transport=httpx.MockTransport(mock_handler))
    assert client.is_authenticated()
    assert secret_token not in repr(client)
    assert secret_token not in str(client)

    meta = client.get_repository_metadata("o", "r")
    assert meta is not None


def test_github_client_rate_limit_handling() -> None:
    """Test detection of rate limit responses (HTTP 429 / 403)."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        headers = {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1600000000"}
        return httpx.Response(403, headers=headers, json={"message": "API rate limit exceeded"})

    client = GitHubClient(transport=httpx.MockTransport(mock_handler))
    with pytest.raises(GitHubRateLimitError) as exc_info:
        client.get_repository_metadata("octocat", "Hello-World")

    err = exc_info.value
    assert err.reset_timestamp == 1600000000


def test_github_client_not_found_404() -> None:
    """Test 404 response converted to GitHubNotFoundError."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Not Found"})

    client = GitHubClient(transport=httpx.MockTransport(mock_handler))
    with pytest.raises(GitHubNotFoundError):
        client.get_repository_metadata("nonexistent", "repo")


def test_github_client_auth_error_401() -> None:
    """Test 401 response converted to GitHubAuthError."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Bad credentials"})

    client = GitHubClient(token="invalid_token", transport=httpx.MockTransport(mock_handler))
    with pytest.raises(GitHubAuthError):
        client.get_repository_metadata("org", "private-repo")
