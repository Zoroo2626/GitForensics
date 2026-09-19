"""Regression coverage for scan selection, offline access, and uninspected data."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from gitforensics.cli import app
from gitforensics.engine import run_analysis
from gitforensics.errors import CLIArgumentError
from gitforensics.git import GitRunner, RepositoryExtractor, parse_repository_input
from gitforensics.models import SignatureStatus
from tests.helpers.git_fixtures import add_commit, create_dummy_repo


@pytest.mark.parametrize("rules", ["GF999", "GF001,GF999", "", " ", "GF001,", ","])
def test_invalid_rules_fail_before_extraction(tmp_path: Path, rules: str) -> None:
    with patch("gitforensics.engine.RepositoryExtractor.extract") as extract:
        result = CliRunner().invoke(
            app, ["scan", str(tmp_path), "--rules", rules, "--fail-on", "high"]
        )
    assert result.exit_code == 2
    extract.assert_not_called()


def test_rule_whitespace_is_accepted(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    result = CliRunner().invoke(
        app, ["scan", str(tmp_path), "--offline", "--rules", " GF007 ", "--format", "json"]
    )
    assert result.exit_code == 0
    findings = json.loads(result.stdout)["findings"]
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "GF007"
    assert "unavailable" in findings[0]["description"]


def test_offline_remote_is_rejected_before_extraction() -> None:
    with patch("gitforensics.engine.RepositoryExtractor.extract") as extract:
        with pytest.raises(CLIArgumentError, match="local repository"):
            run_analysis(parse_repository_input("owner/repo"), offline=True)
    extract.assert_not_called()
    result = CliRunner().invoke(app, ["scan", "owner/repo", "--offline"])
    assert result.exit_code == 2


def test_offline_runner_disallows_git_transport(tmp_path: Path) -> None:
    result = GitRunner(allow_network=False).run(
        ["clone", "--", "https://example.invalid/repo.git", str(tmp_path / "clone")],
        check=False,
    )
    assert result.returncode != 0
    assert "transport 'https' not allowed" in result.stderr


def test_extracted_signature_status_is_unknown(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    report, context = run_analysis(
        parse_repository_input(str(tmp_path)), offline=True, rules_filter=["GF007"]
    )
    assert context.history.commits[0].signature_status == SignatureStatus.UNKNOWN
    evidence = report.findings[0].evidence.data
    assert evidence["unsigned_commit_count"] == 0
    assert evidence["unknown_signature_count"] == 1
    assert evidence["signature_coverage_percentage"] is None


@pytest.mark.parametrize("linked_component", [".github", ".github/workflows"])
def test_workflow_directory_cannot_escape_repository(tmp_path: Path, linked_component: str) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    workflow_directory = outside / "workflows" if linked_component == ".github" else outside
    workflow_directory.mkdir(exist_ok=True)
    (workflow_directory / "private.yml").write_text("run: git push --force", encoding="utf-8")
    link = repo / linked_component
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            pytest.skip("Directory symlinks are unavailable on this host.")
        import _winapi

        _winapi.CreateJunction(str(outside), str(link))
    extractor = RepositoryExtractor()
    warnings: list[str] = []
    assert extractor._extract_local_workflows(repo, warnings) == []
    assert any("escaped" in warning for warning in warnings)
    _, workflow_count, _ = extractor._workflow_state_digest(repo, is_bare=False)
    assert workflow_count == 0
