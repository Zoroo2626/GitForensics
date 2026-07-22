"""Adversarial tests for hostile-repository hardening."""

from __future__ import annotations

import base64
import io
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx
import pytest

from gitforensics.compat import UTC
from gitforensics.detectors.base import BaseDetector
from gitforensics.detectors.local.history_modifying_workflows import (
    HistoryModifyingWorkflowsDetector,
)
from gitforensics.engine import run_analysis
from gitforensics.errors import (
    CLIArgumentError,
    GitCommandError,
    GitHubAPIError,
    GitHubNetworkError,
    GitHubResponseLimitError,
    GitOutputLimitError,
    InvalidGitRepositoryError,
    MalformedGitHubResponseError,
    OutputWriteError,
    RepositoryNotFoundError,
    TemporaryCleanupError,
)
from gitforensics.git import (
    GitCommandResult,
    GitRunner,
    RepositoryExtractor,
    parse_repository_input,
)
from gitforensics.github import GitHubClient
from gitforensics.models import (
    AnalysisReport,
    Confidence,
    DetectorResult,
    Evidence,
    Finding,
    OutputFormat,
    RepositoryContext,
    RepositoryInput,
    RepositoryInputType,
    Severity,
    WorkflowFile,
)
from gitforensics.release_analysis import lookup_attestation, parse_release_from_api
from gitforensics.release_models import AttestationState
from gitforensics.reporting import render_report, write_report_to_file
from gitforensics.security import SecurityLimits, sanitize_text
from tests.helpers.git_fixtures import add_commit, create_dummy_repo, make_synthetic_context


def _git_result(
    args: list[str], stdout: str = "", stderr: str = "", code: int = 0
) -> GitCommandResult:
    return GitCommandResult(command=["git", *args], stdout=stdout, stderr=stderr, returncode=code)


def test_malicious_repository_path_controls_are_rejected() -> None:
    with pytest.raises(CLIArgumentError, match="control characters"):
        parse_repository_input("repo\x00--config=evil")
    with pytest.raises(CLIArgumentError, match="control characters"):
        parse_repository_input("repo\nname")


def test_invalid_git_repository_is_typed(tmp_path: Path) -> None:
    repo_input = parse_repository_input(str(tmp_path))
    with pytest.raises(InvalidGitRepositoryError):
        RepositoryExtractor().extract(repo_input)


def test_malformed_git_output_isolated_as_warning(tmp_path: Path) -> None:
    class MalformedRunner:
        def run(self, args, cwd=None, timeout=None, check=True):
            del cwd, timeout, check
            if args[:2] == ["rev-parse", "--git-dir"]:
                return _git_result(args, ".git\nfalse\n")
            if args[:2] == ["rev-parse", "HEAD"]:
                return _git_result(args, "a" * 40 + "\n")
            if args[0] == "log" and any("--format=tformat:" in arg for arg in args):
                return _git_result(args, "only\x00three\x00fields\x00")
            if args[0] == "log":
                return _git_result(args)
            return _git_result(args)

    repo_input = RepositoryInput(str(tmp_path), RepositoryInputType.LOCAL, str(tmp_path))
    history = RepositoryExtractor(runner=MalformedRunner()).extract(repo_input)  # type: ignore[arg-type]
    assert history.commits == []
    assert any("Malformed Git log" in warning for warning in history.warnings)


def test_git_history_failure_is_not_silently_trusted(tmp_path: Path) -> None:
    class FailingRunner:
        def run(self, args, cwd=None, timeout=None, check=True):
            del cwd, timeout, check
            if args[:2] == ["rev-parse", "--git-dir"]:
                return _git_result(args, ".git\nfalse\n")
            if args[:2] == ["rev-parse", "HEAD"]:
                return _git_result(args, "a" * 40 + "\n")
            return _git_result(args, stderr="corrupt object", code=128)

    repo_input = RepositoryInput(str(tmp_path), RepositoryInputType.LOCAL, str(tmp_path))
    with pytest.raises(GitCommandError, match="history traversal failed"):
        RepositoryExtractor(runner=FailingRunner()).extract(repo_input)  # type: ignore[arg-type]


def test_git_output_limit_terminates_process() -> None:
    process = MagicMock()
    process.stdout = io.BytesIO(b"x" * 256)
    process.stderr = io.BytesIO()
    process.wait.return_value = 0
    process.returncode = -9
    runner = GitRunner(max_stdout_bytes=32)
    with patch("subprocess.Popen", return_value=process):
        with pytest.raises(GitOutputLimitError, match="output exceeded"):
            runner.run(["version"])
    process.kill.assert_called()


def test_git_environment_and_repository_config_are_neutralized(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path, message="one")
    add_commit(tmp_path, filename="two.txt", message="two")
    canary = tmp_path / "external-diff-ran"
    script = tmp_path / "malicious-diff.sh"
    script.write_text(f"#!/bin/sh\nprintf pwned > '{canary.as_posix()}'\n", encoding="utf-8")
    script.chmod(0o755)
    subprocess.run(
        ["git", "config", "diff.external", str(script)],
        cwd=tmp_path,
        check=True,
        shell=False,
    )
    with patch.dict(os.environ, {"GIT_DIR": str(tmp_path / "missing"), "GIT_CONFIG_COUNT": "999"}):
        history = RepositoryExtractor().extract(parse_repository_input(str(tmp_path)))
    assert len(history.commits) == 2
    assert not canary.exists()


def test_shell_metacharacters_remain_one_git_argument(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    canary = tmp_path / "shell-injection"
    result = GitRunner().run(
        ["rev-parse", "--verify", f"HEAD;echo pwned>{canary}"],
        cwd=tmp_path,
        check=False,
    )
    assert result.returncode != 0
    assert not canary.exists()


def test_signature_helper_format_is_not_requested(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    commands: list[list[str]] = []
    runner = GitRunner()
    real_run = runner.run

    def recording_run(args, cwd=None, timeout=None, check=True):
        commands.append(args)
        return real_run(args, cwd=cwd, timeout=timeout, check=check)

    with patch.object(runner, "run", side_effect=recording_run):
        RepositoryExtractor(runner=runner).extract(parse_repository_input(str(tmp_path)))
    flattened = " ".join(arg for command in commands for arg in command)
    assert "%G?" not in flattened
    assert "--show-signature" not in flattened


def test_workflow_symlink_escape_is_ignored(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    outside = tmp_path.parent / f"{tmp_path.name}-outside.yml"
    outside.write_text("run: git push --force", encoding="utf-8")
    link = workflows / "escape.yml"
    try:
        link.symlink_to(outside)
    except OSError:
        link.write_text("run: git push --force", encoding="utf-8")
        real_is_symlink = Path.is_symlink

        def fake_is_symlink(path: Path) -> bool:
            return path == link or real_is_symlink(path)

        with patch.object(Path, "is_symlink", fake_is_symlink):
            history = RepositoryExtractor().extract(parse_repository_input(str(tmp_path)))
    else:
        history = RepositoryExtractor().extract(parse_repository_input(str(tmp_path)))
    assert history.workflows == []
    assert any("Symbolic-link" in warning for warning in history.warnings)


def test_temporary_cleanup_failure_is_typed(tmp_path: Path) -> None:
    repo_input = parse_repository_input("owner/repo")
    extractor = RepositoryExtractor()
    clone_error = GitCommandError("failed")
    with patch("tempfile.mkdtemp", return_value=str(tmp_path / "clone")):
        with patch.object(extractor.runner, "run", side_effect=clone_error):
            with patch("shutil.rmtree", side_effect=OSError("denied")):
                with pytest.raises(TemporaryCleanupError, match="cleanup failed"):
                    extractor.extract(repo_input)


def test_commit_processing_limit_is_applied_by_git(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    for index in range(4):
        add_commit(tmp_path, filename=f"{index}.txt", message=str(index))
    limits = SecurityLimits(max_commits=2)
    history = RepositoryExtractor(limits=limits).extract(parse_repository_input(str(tmp_path)))
    assert len(history.commits) == 2
    assert history.is_limited
    assert "2" in history.limit_reason


def test_tag_enumeration_is_bounded_and_parsed_without_ref_execution(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    subprocess.run(
        ["git", "tag", "v1.0.0"],
        cwd=tmp_path,
        check=True,
        shell=False,
    )
    subprocess.run(
        ["git", "tag", "-a", "v1.0.1", "-m", "annotated"],
        cwd=tmp_path,
        check=True,
        shell=False,
    )
    history = RepositoryExtractor(limits=SecurityLimits(max_tags=10)).extract(
        parse_repository_input(str(tmp_path))
    )
    assert {tag.short_name for tag in history.tags} == {"v1.0.0", "v1.0.1"}
    assert any(tag.is_annotated for tag in history.tags)


def test_oversized_workflow_file_is_skipped(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "large.yml").write_bytes(b"x" * 65)
    limits = SecurityLimits(max_workflow_file_bytes=64)
    history = RepositoryExtractor(limits=limits).extract(parse_repository_input(str(tmp_path)))
    assert history.workflows == []
    assert any("Oversized workflow" in warning for warning in history.warnings)


def test_malformed_yaml_is_static_text_and_does_not_crash() -> None:
    malformed = "!!python/object/apply:os.system ['echo pwned'\n{{{{"
    workflow = WorkflowFile(
        ".github/workflows/bad.yml",
        "bad.yml",
        malformed,
        malformed.splitlines(),
    )
    context = make_synthetic_context([])
    context.history.workflows = [workflow]
    result = HistoryModifyingWorkflowsDetector().analyze(context)
    assert isinstance(result, DetectorResult)


def test_workflow_analysis_never_imports_or_calls_yaml_loader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_yaml = SimpleNamespace(load=MagicMock(side_effect=AssertionError("unsafe loader")))
    monkeypatch.setitem(sys.modules, "yaml", fake_yaml)
    workflow = WorkflowFile("w.yml", "w.yml", "run: git push --force", ["run: git push --force"])
    context = make_synthetic_context([])
    context.history.workflows = [workflow]
    HistoryModifyingWorkflowsDetector().analyze(context)
    fake_yaml.load.assert_not_called()


def test_api_token_is_redacted_from_network_exception() -> None:
    token = "ghp_" + "a" * 36

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"connection failed with {token}", request=request)

    client = GitHubClient(token=token, transport=httpx.MockTransport(handler), max_retries=0)
    with pytest.raises(GitHubNetworkError) as caught:
        client.get_repository_metadata("owner", "repo")
    assert token not in str(caught.value)
    assert "[REDACTED]" in str(caught.value)


def test_api_errors_and_redirects_are_typed_without_following() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(302, headers={"location": "https://evil.example/steal"})

    token = "github_pat_" + "b" * 36
    client = GitHubClient(token=token, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubAPIError, match="redirect"):
        client.get_repository_metadata("owner", "repo")
    assert calls == 1


def test_malformed_and_oversized_api_responses_are_rejected() -> None:
    malformed = GitHubClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"{"))
    )
    with pytest.raises(MalformedGitHubResponseError):
        malformed.get_repository_metadata("owner", "repo")

    limits = SecurityLimits(max_api_response_bytes=64)
    oversized = GitHubClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"x" * 65)),
        limits=limits,
    )
    with pytest.raises(GitHubResponseLimitError):
        oversized.get_repository_metadata("owner", "repo")


def test_bounded_workflow_download_from_approved_host() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.host == "api.github.com":
            return httpx.Response(
                200,
                json=[
                    {
                        "type": "file",
                        "name": "audit.yml",
                        "size": 20,
                        "download_url": "https://raw.githubusercontent.com/o/r/main/audit.yml",
                    }
                ],
            )
        return httpx.Response(200, content=b"run: git push --force")

    client = GitHubClient(transport=httpx.MockTransport(handler))
    workflows = client.get_workflow_files("o", "r")
    assert len(workflows) == 1
    assert workflows[0].path == ".github/workflows/audit.yml"
    assert len(calls) == 2


def test_successful_github_enrichment_remains_bounded_and_complete(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/contents/.github/workflows") or path.endswith("/releases"):
            return httpx.Response(200, json=[])
        return httpx.Response(
            200,
            json={
                "id": 1,
                "owner": {"login": "o"},
                "name": "r",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "pushed_at": "2026-01-01T00:00:00Z",
                "default_branch": "main",
            },
        )

    client = GitHubClient(transport=httpx.MockTransport(handler))
    with patch("gitforensics.engine._extract_github_owner_repo", return_value=("o", "r")):
        report, context = run_analysis(
            parse_repository_input(str(tmp_path)),
            github_client=client,
        )
    assert report.github_metadata_available
    assert context.github_metadata is not None
    assert report.total_releases == 0
    assert report.is_complete, report.incomplete_analysis_reasons


def test_normal_local_workflow_is_read_as_bounded_static_text(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "audit.YAML").write_text("run: echo safe", encoding="utf-8")
    history = RepositoryExtractor().extract(parse_repository_input(str(tmp_path)))
    assert len(history.workflows) == 1
    assert history.workflows[0].content == "run: echo safe"


@pytest.mark.parametrize(
    ("attested_uri", "expected"),
    [
        ("https://github.com/o/r", AttestationState.MATCHING_ATTESTATION_FOUND),
        ("https://github.com/other/repo", AttestationState.REPOSITORY_IDENTITY_MISMATCH),
    ],
)
def test_attestation_response_is_bounded_and_schema_checked(
    attested_uri: str, expected: AttestationState
) -> None:
    digest = "a" * 64
    release = parse_release_from_api(
        {
            "id": 1,
            "tag_name": "v1",
            "assets": [
                {
                    "id": 2,
                    "name": "app.zip",
                    "size": 3,
                    "digest": f"sha256:{digest}",
                    "created_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-01T00:00:00Z",
                    "uploader": {"login": "u"},
                    "browser_download_url": "https://objects.githubusercontent.com/app.zip",
                }
            ],
        }
    )
    predicate = {
        "predicate": {
            "buildDefinition": {
                "externalParameters": {"workflow": {"ref": "refs/heads/main"}},
                "resolvedDependencies": [{"uri": attested_uri}],
            }
        }
    }
    encoded = base64.b64encode(json.dumps(predicate).encode()).decode().rstrip("=")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer token-value"
        return httpx.Response(
            200,
            json={"attestations": [{"bundle": {"dsseEnvelope": {"payload": encoded}}}]},
        )

    state, subject, repository, workflow = lookup_attestation(
        release.assets[0],
        "o",
        "r",
        httpx.MockTransport(handler),
        1.0,
        "token-value",
        "https://api.github.com",
    )
    assert state == expected
    assert subject == digest
    assert repository == attested_uri
    assert workflow == "refs/heads/main"


def _hostile_report(secret: str) -> AnalysisReport:
    finding = Finding(
        "GF999",
        "[bold red]Injected[/bold red] \x1b[31m",
        f"authorization: Bearer {secret}\u202e",
        Severity.LOW,
        Confidence.HIGH,
        Evidence({"password": "password=test-password-value", "nested": [secret, "x" * 2_000]}),
    )
    return AnalysisReport(
        repository="https://user:password@github.com/o/r.git?token=leak",
        findings=[finding],
        incomplete_analysis_reasons=[f"failed with {secret}\x1b[2J"],
    )


def test_json_report_redacts_secrets_credentials_and_controls() -> None:
    secret = "ghp_" + "c" * 36
    rendered = render_report(_hostile_report(secret), output_format=OutputFormat.JSON)
    parsed = json.loads(rendered)
    assert secret not in rendered
    assert "test-password-value" not in rendered
    assert "password@" not in parsed["repository"]
    assert "\x1b" not in rendered
    assert "\u202e" not in rendered
    assert "[REDACTED]" in rendered
    assert len(parsed["findings"][0]["evidence"]["nested"][1]) <= 512


def test_terminal_report_treats_markup_as_data_and_redacts() -> None:
    secret = "github_pat_" + "d" * 36
    rendered = render_report(
        _hostile_report(secret), output_format=OutputFormat.TERMINAL, no_color=True, verbose=True
    )
    assert secret not in rendered
    assert "test-password-value" not in rendered
    assert "\x1b" not in rendered
    assert "Injected" in rendered
    assert "[bold red]Injected[/bold red]" in rendered


def test_output_symlink_is_never_followed(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("original", encoding="utf-8")
    link = tmp_path / "report.json"
    try:
        link.symlink_to(target)
    except OSError:
        link.write_text("not a real link", encoding="utf-8")
        real_is_symlink = Path.is_symlink

        def fake_is_symlink(path: Path) -> bool:
            return path == link or real_is_symlink(path)

        with patch.object(Path, "is_symlink", fake_is_symlink):
            with pytest.raises(OutputWriteError, match="symbolic-link"):
                write_report_to_file("replacement", str(link), force=True)
    else:
        with pytest.raises(OutputWriteError, match="symbolic-link"):
            write_report_to_file("replacement", str(link), force=True)
    assert target.read_text(encoding="utf-8") == "original"


def test_windows_reserved_and_unicode_edge_cases_are_safe(tmp_path: Path) -> None:
    with pytest.raises(RepositoryNotFoundError):
        parse_repository_input(str(tmp_path / "CON"))
    hostile = "normal\u202eexe\x00\x1b[31m snowman=\u2603"
    cleaned = sanitize_text(hostile)
    assert "\u202e" not in cleaned
    assert "\x00" not in cleaned
    assert "\x1b" not in cleaned
    assert "\u2603" in cleaned


class _FailingDetector(BaseDetector):
    def get_rule_id(self) -> str:
        return "GF-FAIL"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        del context
        raise RuntimeError("token=detector-secret")


class _HealthyDetector(BaseDetector):
    def get_rule_id(self) -> str:
        return "GF-OK"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        del context
        return DetectorResult(
            rule_id=self.get_rule_id(),
            findings=[
                Finding(
                    self.get_rule_id(),
                    "Healthy detector ran",
                    "Independent result",
                    Severity.INFO,
                    Confidence.HIGH,
                    Evidence({"ok": True}),
                )
            ],
        )


def test_detector_failure_isolation_and_determinism(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    repo_input = parse_repository_input(str(tmp_path))

    def clock() -> datetime:
        return datetime(2026, 1, 1, tzinfo=UTC)

    def analyze_once() -> AnalysisReport:
        times = iter((10.0, 11.0))
        report, _ = run_analysis(
            repo_input,
            detectors=[_FailingDetector(), _HealthyDetector()],
            offline=True,
            clock=clock,
            timer=lambda: next(times),
        )
        return report

    first = analyze_once()
    second = analyze_once()
    assert "GF-FAIL" in first.failed_detectors
    assert any(finding.rule_id == "GF-OK" for finding in first.findings)
    assert not first.is_complete
    assert "detector-secret" not in json.dumps(first.to_dict())
    assert first.to_dict() == second.to_dict()
