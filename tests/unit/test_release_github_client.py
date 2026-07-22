"""Unit tests for GitHub release API client methods."""

import httpx
import pytest

from gitforensics.errors import (
    GitHubNotFoundError,
    GitHubRateLimitError,
    MalformedGitHubResponseError,
)
from gitforensics.github import GitHubClient


# Helper to build a minimal release payload
def _release_payload(
    release_id: int = 1,
    name: str = "v1.0.0",
    tag_name: str = "v1.0.0",
    draft: bool = False,
    prerelease: bool = False,
    published_at: str = "2026-01-01T00:00:00Z",
    assets: list | None = None,
) -> dict:
    return {
        "id": release_id,
        "name": name,
        "tag_name": tag_name,
        "target_commitish": "main",
        "draft": draft,
        "prerelease": prerelease,
        "created_at": "2026-01-01T00:00:00Z",
        "published_at": published_at,
        "author": {"login": "octocat"},
        "body": "Release notes.",
        "tarball_url": "",
        "zipball_url": "",
        "assets": assets or [],
    }


def test_get_releases_empty_list() -> None:
    """Test fetching releases when repo has none."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        assert "/releases" in str(request.url)
        return httpx.Response(200, json=[])

    client = GitHubClient(transport=httpx.MockTransport(mock_handler))
    releases = client.get_releases("owner", "repo")
    assert releases == []


def test_get_releases_one_release() -> None:
    """Test fetching a single release."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[_release_payload()])

    client = GitHubClient(transport=httpx.MockTransport(mock_handler))
    releases = client.get_releases("owner", "repo")
    assert len(releases) == 1
    assert releases[0]["tag_name"] == "v1.0.0"


def test_get_releases_multiple_ordered() -> None:
    """Test fetching multiple releases returns all of them."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=[
                _release_payload(release_id=1, name="v1.0.0", tag_name="v1.0.0"),
                _release_payload(release_id=2, name="v1.1.0", tag_name="v1.1.0"),
                _release_payload(release_id=3, name="v2.0.0", tag_name="v2.0.0"),
            ],
        )

    client = GitHubClient(transport=httpx.MockTransport(mock_handler))
    releases = client.get_releases("owner", "repo")
    assert len(releases) == 3
    assert {r["tag_name"] for r in releases} == {"v1.0.0", "v1.1.0", "v2.0.0"}


def test_get_releases_draft_returned_if_api_returns_it() -> None:
    """Test that draft releases are included when the API returns them (auth-dependent)."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        # Simulate API returning a draft release for an authenticated user
        return httpx.Response(200, json=[_release_payload(draft=True)])

    client = GitHubClient(token="ghp_token", transport=httpx.MockTransport(mock_handler))
    releases = client.get_releases("owner", "repo")
    assert len(releases) == 1
    assert releases[0]["draft"] is True


def test_get_releases_pagination() -> None:
    """Test get_releases follows pagination Link header correctly."""
    call_count = [0]

    def mock_handler(request: httpx.Request) -> httpx.Response:
        call_count[0] += 1
        if call_count[0] == 1:
            return httpx.Response(
                200,
                json=[_release_payload(release_id=1, tag_name="v1.0.0")],
                headers={"Link": '<https://api.github.com/repos/o/r/releases?page=2>; rel="next"'},
            )
        else:
            # Second page has no Link header (no next page)
            return httpx.Response(200, json=[_release_payload(release_id=2, tag_name="v2.0.0")])

    client = GitHubClient(
        base_url="https://api.github.com",
        transport=httpx.MockTransport(mock_handler),
    )
    releases = client.get_releases("o", "r")
    assert len(releases) == 2
    assert {r["tag_name"] for r in releases} == {"v1.0.0", "v2.0.0"}
    assert call_count[0] == 2


def test_get_releases_rate_limit() -> None:
    """Test release fetch handles rate limit responses correctly."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            json={"message": "Rate limit exceeded"},
            headers={"X-RateLimit-Reset": "1700000000"},
        )

    client = GitHubClient(transport=httpx.MockTransport(mock_handler))
    with pytest.raises(GitHubRateLimitError):
        client.get_releases("owner", "repo")


def test_get_releases_not_found() -> None:
    """Test release fetch on non-existent repo returns GitHubNotFoundError."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Not Found"})

    client = GitHubClient(transport=httpx.MockTransport(mock_handler))
    with pytest.raises(GitHubNotFoundError):
        client.get_releases("nonexistent", "repo")


def test_get_releases_timeout() -> None:
    """Test release fetch handles timeout errors."""
    from gitforensics.errors import GitHubNetworkError

    def mock_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Simulated read timeout", request=request)

    client = GitHubClient(transport=httpx.MockTransport(mock_handler), max_retries=0)
    with pytest.raises(GitHubNetworkError):
        client.get_releases("owner", "repo")


def test_get_releases_malformed_response() -> None:
    """Test that malformed non-list JSON response does not crash."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        # Return a dict instead of a list - should be handled gracefully
        return httpx.Response(200, json={"message": "unexpected format"})

    client = GitHubClient(transport=httpx.MockTransport(mock_handler))
    with pytest.raises(MalformedGitHubResponseError):
        client.get_releases("owner", "repo")
