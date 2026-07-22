"""Unit tests for remote repository cloning, temporary directory cleanup, and mocking."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from gitforensics.errors import GitCloneError, GitCommandError
from gitforensics.git import RepositoryExtractor, parse_repository_input
from gitforensics.models import ExtractedHistory, RepositoryInputType
from tests.helpers.git_fixtures import add_commit, create_dummy_repo


def test_remote_clone_mocked_success(tmp_path: Path) -> None:
    """Test requirements 19, 26, 27: mock remote clone, no live network, cleanup on success."""
    cloned_dummy = tmp_path / "dummy_cloned"
    create_dummy_repo(cloned_dummy)
    add_commit(cloned_dummy, message="Remote commit")

    repo_input = parse_repository_input("https://github.com/org/mock-repo.git")
    assert repo_input.input_type == RepositoryInputType.REMOTE

    extractor = RepositoryExtractor()
    real_run = extractor.runner.run

    def mock_clone(args, cwd=None, timeout=None, check=True):
        if args and args[0] == "clone":
            assert "--no-checkout" in args
            assert repo_input.resolved_path_or_url in args
            return MagicMock(stdout="", stderr="", returncode=0)
        return real_run(args, cwd=cwd, timeout=timeout, check=check)

    import tempfile

    real_mkdtemp = tempfile.mkdtemp

    def mock_mkdtemp_success(*args, **kwargs):
        if kwargs.get("prefix") == "gitforensics_clone_":
            return str(cloned_dummy)
        return real_mkdtemp(*args, **kwargs)

    with patch.object(extractor.runner, "run", side_effect=mock_clone):
        with patch("tempfile.mkdtemp", side_effect=mock_mkdtemp_success):
            with patch("shutil.rmtree") as mock_rmtree:
                history = extractor.extract(repo_input)
                assert isinstance(history, ExtractedHistory)
                assert history.repository_path == "https://github.com/org/mock-repo.git"
                assert len(history.commits) == 1
                assert mock_rmtree.call_args_list[-1].args[0] == cloned_dummy


def test_remote_clone_mocked_failure_cleanup(tmp_path: Path) -> None:
    """Test requirements 20, 26, 27: cleanup temp directory after clone failure."""
    dummy_dir = tmp_path / "dummy_fail"
    dummy_dir.mkdir()

    repo_input = parse_repository_input("https://github.com/org/fail-repo.git")
    extractor = RepositoryExtractor()

    def mock_failing_clone(args, cwd=None, timeout=None, check=True):
        if args and args[0] == "clone":
            raise GitCommandError(
                "Clone failed",
                command=["git", "clone"],
                returncode=128,
                stderr="Repo not found",
            )
        return MagicMock(stdout="", stderr="", returncode=0)

    import tempfile

    real_mkdtemp = tempfile.mkdtemp

    def mock_mkdtemp_fail(*args, **kwargs):
        if kwargs.get("prefix") == "gitforensics_clone_":
            return str(dummy_dir)
        return real_mkdtemp(*args, **kwargs)

    with patch.object(extractor.runner, "run", side_effect=mock_failing_clone):
        with patch("tempfile.mkdtemp", side_effect=mock_mkdtemp_fail):
            with patch("shutil.rmtree") as mock_rmtree:
                with pytest.raises(GitCloneError, match="Failed to clone"):
                    extractor.extract(repo_input)
                mock_rmtree.assert_called_once()
