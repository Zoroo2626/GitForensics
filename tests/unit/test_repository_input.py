"""Unit tests for repository input parsing, validation, and URL/path handling."""

from pathlib import Path

import pytest

from gitforensics.errors import CLIArgumentError, RepositoryNotFoundError
from gitforensics.git import parse_repository_input
from gitforensics.models import RepositoryInputType


def test_github_shorthand_resolution() -> None:
    """Test GitHub shorthand (owner/repo) normalization."""
    parsed = parse_repository_input("octocat/Hello-World")
    assert parsed.input_type == RepositoryInputType.REMOTE
    assert parsed.resolved_path_or_url == "https://github.com/octocat/Hello-World.git"


def test_valid_github_urls() -> None:
    """Test valid GitHub URLs parsing."""
    url1 = "https://github.com/google/antigravity"
    parsed1 = parse_repository_input(url1)
    assert parsed1.input_type == RepositoryInputType.REMOTE
    assert parsed1.resolved_path_or_url == "https://github.com/google/antigravity.git"

    url2 = "git@github.com:torvalds/linux.git"
    parsed2 = parse_repository_input(url2)
    assert parsed2.input_type == RepositoryInputType.REMOTE
    assert parsed2.resolved_path_or_url == "https://github.com/torvalds/linux.git"


def test_malformed_github_urls() -> None:
    """Test requirement 15: malformed GitHub repository URLs."""
    with pytest.raises(CLIArgumentError, match="Malformed or unsupported GitHub URL"):
        parse_repository_input("https://github.com/")

    with pytest.raises(CLIArgumentError, match="Malformed or unsupported GitHub URL"):
        parse_repository_input("https://github.com/org/repo/extra/path")


def test_unsupported_url_schemes() -> None:
    """Test requirement 16: unsupported URL schemes."""
    for scheme_url in [
        "ftp://github.com/user/repo",
        "file:///tmp/repo",
        "ssh://git@github.com/user/repo",
        "svn://repo.example.com/project",
    ]:
        with pytest.raises(CLIArgumentError, match="Unsupported URL scheme"):
            parse_repository_input(scheme_url)


def test_malformed_repository_paths() -> None:
    """Test requirement 14: malformed/non-existent repository paths."""
    with pytest.raises(RepositoryNotFoundError, match="does not exist"):
        parse_repository_input("/nonexistent_directory_abc123/repo")


def test_windows_paths_with_spaces(tmp_path: Path) -> None:
    """Test requirement 23: Windows paths containing spaces."""
    target = tmp_path / "Example Work" / "Desktop Projects" / "My Repo"
    target.mkdir(parents=True)
    win_path = str(target)
    parsed = parse_repository_input(win_path)
    assert parsed.input_type == RepositoryInputType.LOCAL
    assert parsed.resolved_path_or_url == str(target.resolve())
