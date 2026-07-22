"""Unit tests for repository input parsing, Windows paths, and invalid inputs."""

from pathlib import Path

import pytest

from gitforensics.errors import CLIArgumentError, RepositoryNotFoundError
from gitforensics.git import parse_repository_input
from gitforensics.models import RepositoryInputType


def test_windows_path_inputs(tmp_path: Path) -> None:
    """Test parsing Windows style paths."""
    first = tmp_path / "Project"
    first.mkdir()
    win_input_1 = str(first)
    parsed_1 = parse_repository_input(win_input_1)
    assert parsed_1.input_type == RepositoryInputType.LOCAL
    assert Path(parsed_1.resolved_path_or_url) == first.resolve()

    second = tmp_path / "GitRepo"
    second.mkdir()
    win_input_2 = str(second).replace("\\", "/")
    parsed_2 = parse_repository_input(win_input_2)
    assert parsed_2.input_type == RepositoryInputType.LOCAL
    assert Path(parsed_2.resolved_path_or_url) == second.resolve()


def test_remote_url_inputs() -> None:
    """Test parsing remote GitHub URLs."""
    url_1 = "https://github.com/owner/repo.git"
    parsed_1 = parse_repository_input(url_1)
    assert parsed_1.input_type == RepositoryInputType.REMOTE
    assert parsed_1.resolved_path_or_url == "https://github.com/owner/repo.git"

    url_2 = "git@github.com:owner/repo.git"
    parsed_2 = parse_repository_input(url_2)
    assert parsed_2.input_type == RepositoryInputType.REMOTE
    assert parsed_2.resolved_path_or_url == "https://github.com/owner/repo.git"


def test_invalid_repository_inputs(tmp_path: Path) -> None:
    """Test invalid repository input handling."""
    # Empty string
    with pytest.raises(CLIArgumentError, match="cannot be empty"):
        parse_repository_input("")

    # Non-existent path
    with pytest.raises(RepositoryNotFoundError, match="does not exist"):
        parse_repository_input(str(tmp_path / "nonexistent"))

    # File path instead of directory
    file_path = tmp_path / "dummy.txt"
    file_path.write_text("hello")
    with pytest.raises(CLIArgumentError, match="not a directory"):
        parse_repository_input(str(file_path))


def test_valid_local_directory(tmp_path: Path) -> None:
    """Test parsing existing local directory path."""
    parsed = parse_repository_input(str(tmp_path))
    assert parsed.input_type == RepositoryInputType.LOCAL
    assert parsed.resolved_path_or_url == str(tmp_path.resolve())
