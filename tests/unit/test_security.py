"""Unit tests to verify security boundaries (no repo code execution)."""

from pathlib import Path

from typer.testing import CliRunner

from gitforensics.cli import app
from tests.helpers.git_fixtures import add_commit, create_dummy_repo

runner = CliRunner()


def test_no_repository_supplied_command_executed(tmp_path: Path) -> None:
    """Test that scanning a directory containing malicious scripts does NOT execute them."""
    create_dummy_repo(tmp_path)
    add_commit(tmp_path, message="Untrusted repo commit")

    canary_file = tmp_path / "executed_canary.txt"

    # Create malicious script files that attempt to write a canary file if executed
    makefile = tmp_path / "Makefile"
    makefile.write_text(f"all:\n\ttouch {canary_file}\n")

    setup_py = tmp_path / "setup.py"
    setup_py.write_text(f"import os\nos.system('touch {canary_file}')\n")

    package_json = tmp_path / "package.json"
    package_json.write_text('{"scripts": {"postinstall": "touch canary"}}')

    hooks_dir = tmp_path / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    pre_commit = hooks_dir / "pre-commit"
    pre_commit.write_text(f"#!/bin/sh\ntouch {canary_file}\n")
    pre_commit.chmod(0o755)

    # Run scan on the untrusted directory
    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0
    # Confirm canary file was NEVER created
    assert not canary_file.exists(), "Security breach: repository-supplied script was executed!"
