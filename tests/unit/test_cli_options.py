"""Unit tests for CLI options, exit codes, and threshold enforcement."""

import json
from pathlib import Path

from typer.testing import CliRunner

from gitforensics.cli import app
from tests.helpers.git_fixtures import add_commit, create_dummy_repo

runner = CliRunner()


def test_cli_help_and_version() -> None:
    """Test --help and --version options return exit code 0."""
    res_help = runner.invoke(app, ["--help"])
    assert res_help.exit_code == 0
    assert "GitForensics" in res_help.stdout

    res_ver = runner.invoke(app, ["--version"])
    assert res_ver.exit_code == 0
    assert "version" in res_ver.stdout


def test_cli_scan_help() -> None:
    """Test scan --help returns exit code 0."""
    res = runner.invoke(app, ["scan", "--help"])
    assert res.exit_code == 0
    assert "--fail-on" in res.stdout
    assert "--offline" in res.stdout


def test_cli_scan_normal_local_repo(tmp_path: Path) -> None:
    """Test scanning a local repository returns exit code 0."""
    create_dummy_repo(tmp_path)
    add_commit(tmp_path, message="First commit")

    res = runner.invoke(app, ["scan", str(tmp_path)])
    assert res.exit_code == 0
    assert "GitForensics Analysis Report" in res.stdout


def test_cli_scan_format_json_stdout(tmp_path: Path) -> None:
    """Test scan --format json outputs valid JSON directly to stdout."""
    create_dummy_repo(tmp_path)
    add_commit(tmp_path, message="First commit")

    res = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert res.exit_code == 0

    data = json.loads(res.stdout)
    assert data["schema_version"] == "1.0.0"
    assert data["risk_score"] >= 0


def test_cli_scan_output_file(tmp_path: Path) -> None:
    """Test scan --output writes report file and returns exit code 0."""
    create_dummy_repo(tmp_path)
    add_commit(tmp_path, message="First commit")

    out_file = tmp_path / "out_report.json"
    res = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--output", str(out_file)])
    assert res.exit_code == 0
    assert out_file.exists()

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0.0"


def test_cli_scan_incompatible_quiet_and_verbose(tmp_path: Path) -> None:
    """Test specifying both --quiet and --verbose yields exit code 2."""
    create_dummy_repo(tmp_path)
    res = runner.invoke(app, ["scan", str(tmp_path), "--quiet", "--verbose"])
    assert res.exit_code == 2


def test_cli_scan_fail_on_threshold(tmp_path: Path) -> None:
    """Test --fail-on exit code 5 when findings meet or exceed specified threshold."""
    create_dummy_repo(tmp_path)
    # Add 10 commits total, 3 with mismatch -> 30% mismatch percentage -> MEDIUM severity
    for i in range(1, 11):
        if i <= 3:
            add_commit(
                tmp_path,
                filename=f"m{i}.txt",
                message=f"Commit {i}",
                author_email="author@example.com",
                committer_email="committer@example.com",
            )
        else:
            add_commit(
                tmp_path,
                filename=f"c{i}.txt",
                message=f"Commit {i}",
                author_email="same@example.com",
                committer_email="same@example.com",
            )

    # --fail-on high -> exit code 0 because finding is MEDIUM
    res_high = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "high"])
    assert res_high.exit_code == 0

    # --fail-on medium -> exit code 5 because finding is MEDIUM
    res_med = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "medium"])
    assert res_med.exit_code == 5
