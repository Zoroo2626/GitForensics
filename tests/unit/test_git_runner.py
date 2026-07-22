"""Unit tests for GitRunner execution, error conversion, security flags, and timeouts."""

import io
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from gitforensics.errors import GitCommandError, GitTimeoutError
from gitforensics.git import GitRunner
from tests.helpers.git_fixtures import create_dummy_repo


def test_git_runner_success(tmp_path: Path) -> None:
    """Test successful Git command execution."""
    create_dummy_repo(tmp_path)
    runner = GitRunner()
    res = runner.run(["rev-parse", "--is-inside-work-tree"], cwd=tmp_path)
    assert res.returncode == 0
    assert res.stdout.strip() == "true"
    assert res.command[0:3] == ["git", "--no-pager", "--no-replace-objects"]
    assert f"core.hooksPath={os.devnull}" in res.command


def test_git_runner_command_failure(tmp_path: Path) -> None:
    """Test requirement 17: Git command failures raise GitCommandError."""
    create_dummy_repo(tmp_path)
    runner = GitRunner()
    with pytest.raises(GitCommandError) as exc_info:
        runner.run(["rev-parse", "--verify", "nonexistent_branch_12345"], cwd=tmp_path)

    err = exc_info.value
    assert err.returncode != 0
    assert "rev-parse" in " ".join(err.command)


def test_git_runner_timeout() -> None:
    """Test requirement 18: Git command timeouts raise GitTimeoutError."""
    runner = GitRunner(default_timeout=0.001)
    process = MagicMock()
    process.stdout = io.BytesIO()
    process.stderr = io.BytesIO()
    process.wait.side_effect = [subprocess.TimeoutExpired(["git"], 0.001), 0]
    process.returncode = -9
    with patch("subprocess.Popen", return_value=process):
        with pytest.raises(GitTimeoutError, match="timed out"):
            runner.run(["log"], timeout=0.001)
    process.kill.assert_called_once()


def test_shell_true_never_used(tmp_path: Path) -> None:
    """Test requirement 21: verify shell=False is explicitly passed to subprocess.Popen."""
    create_dummy_repo(tmp_path)
    runner = GitRunner()

    with patch("subprocess.Popen", wraps=subprocess.Popen) as mock_run:
        runner.run(["version"], cwd=tmp_path)
        assert mock_run.called
        kwargs = mock_run.call_args.kwargs
        assert kwargs.get("shell") is False, "Security violation: shell must be False!"


def test_no_checkout_or_submodules_executed(tmp_path: Path) -> None:
    """Test requirement 22: verify core.hooksPath=/dev/null and isolated environment variables."""
    create_dummy_repo(tmp_path)
    runner = GitRunner()

    with patch("subprocess.Popen", wraps=subprocess.Popen) as mock_run:
        runner.run(["status"], cwd=tmp_path)

        cmd = mock_run.call_args[0][0]
        env = mock_run.call_args.kwargs.get("env", {})

        assert "-c" in cmd
        assert f"core.hooksPath={os.devnull}" in cmd
        assert env.get("GIT_TERMINAL_PROMPT") == "0"
        assert env.get("GIT_ASKPASS") == "echo"
        assert env.get("GIT_CONFIG_NOSYSTEM") == "1"
        assert env.get("GIT_CONFIG_GLOBAL") == os.devnull
        assert env.get("GIT_NO_REPLACE_OBJECTS") == "1"
        assert "GIT_DIR" not in env
