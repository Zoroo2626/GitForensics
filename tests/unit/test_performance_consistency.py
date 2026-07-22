"""Consistency, bounded-performance, and concurrency regression tests."""

from __future__ import annotations

import json
import os
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from gitforensics.analysis_summary import build_analysis_summary, get_analysis_summary
from gitforensics.compat import UTC
from gitforensics.detectors.base import BaseDetector
from gitforensics.detectors.local.regular_intervals import RegularIntervalsDetector
from gitforensics.engine import run_analysis
from gitforensics.errors import OutputWriteError
from gitforensics.git import GitRunner, RepositoryExtractor, parse_repository_input
from gitforensics.github import GitHubClient
from gitforensics.models import (
    AnalysisReport,
    Confidence,
    DetectorResult,
    Evidence,
    Finding,
    OutputFormat,
    RepositoryConsistencyStatus,
    RepositoryContext,
    Severity,
    TagNode,
)
from gitforensics.release_analysis import (
    build_release_resolution_index,
    lookup_attestation,
    parse_release_from_api,
    run_release_analysis,
)
from gitforensics.release_models import AssetVerificationConfig, AttestationState, DigestState
from gitforensics.reporting import render_report, write_report_to_file
from gitforensics.scoring import calculate_risk_score
from gitforensics.security import SecurityLimits, sanitize_text, sanitize_value
from tests.helpers.git_fixtures import (
    add_commit,
    create_dummy_repo,
    make_synthetic_commit,
    make_synthetic_context,
)


def _fixed_clock() -> datetime:
    return datetime(2026, 7, 22, tzinfo=UTC)


def _fixed_timer() -> float:
    return 10.0


class _ChangeHeadDetector(BaseDetector):
    def __init__(self, repo: Path, new_target: str) -> None:
        self.repo = repo
        self.new_target = new_target

    def get_rule_id(self) -> str:
        return "GF-CHANGE-HEAD"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        del context
        subprocess.run(
            ["git", "update-ref", "HEAD", self.new_target],
            cwd=self.repo,
            check=True,
            capture_output=True,
            shell=False,
        )
        return DetectorResult(rule_id=self.get_rule_id())


class _ChangeRefDetector(BaseDetector):
    def __init__(self, repo: Path) -> None:
        self.repo = repo

    def get_rule_id(self) -> str:
        return "GF-CHANGE-REF"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        del context
        subprocess.run(
            ["git", "branch", "consistency-side-ref", "HEAD"],
            cwd=self.repo,
            check=True,
            capture_output=True,
            shell=False,
        )
        return DetectorResult(rule_id=self.get_rule_id())


class _ChangeWorkflowDetector(BaseDetector):
    def __init__(self, workflow: Path) -> None:
        self.workflow = workflow

    def get_rule_id(self) -> str:
        return "GF-CHANGE-WORKFLOW"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        del context
        self.workflow.write_text("name: changed workflow content\n", encoding="utf-8")
        return DetectorResult(rule_id=self.get_rule_id())


class _SummaryIdentityDetector(BaseDetector):
    def get_rule_id(self) -> str:
        return "GF-SUMMARY-ID"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        first = get_analysis_summary(context)
        second = get_analysis_summary(context)
        assert first is second
        return DetectorResult(rule_id=self.get_rule_id())


class _TruncatingDetector(BaseDetector):
    def get_rule_id(self) -> str:
        return "GF-TRUNC"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        finding = Finding(
            self.get_rule_id(),
            "bounded",
            "bounded",
            Severity.INFO,
            Confidence.HIGH,
            Evidence({"ok": True}),
        )
        return DetectorResult(
            rule_id=self.get_rule_id(),
            findings=[finding],
            truncated=True,
            truncation_reason="Synthetic detector reached its configured limit.",
        )


def test_repository_unchanged_during_analysis_is_stable(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    report, context = run_analysis(
        parse_repository_input(str(tmp_path)),
        detectors=[],
        offline=True,
        clock=_fixed_clock,
        timer=_fixed_timer,
    )
    assert context.history.consistency_status == RepositoryConsistencyStatus.STABLE
    assert report.is_complete


def test_head_change_during_analysis_marks_report_incomplete(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    first = add_commit(tmp_path, message="first")
    add_commit(tmp_path, filename="second.txt", message="second")
    report, context = run_analysis(
        parse_repository_input(str(tmp_path)),
        detectors=[_ChangeHeadDetector(tmp_path, first)],
        offline=True,
    )
    assert context.history.consistency_status == RepositoryConsistencyStatus.CHANGED
    assert not report.is_complete
    assert any("not a stable snapshot" in reason for reason in report.incomplete_analysis_reasons)


def test_non_head_ref_change_is_detected(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    report, context = run_analysis(
        parse_repository_input(str(tmp_path)),
        detectors=[_ChangeRefDetector(tmp_path)],
        offline=True,
    )
    assert context.history.consistency_status == RepositoryConsistencyStatus.CHANGED
    assert not report.is_complete


def test_workflow_change_during_analysis_is_detected(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    workflow = tmp_path / ".github" / "workflows" / "audit.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: initial\n", encoding="utf-8")
    report, context = run_analysis(
        parse_repository_input(str(tmp_path)),
        detectors=[_ChangeWorkflowDetector(workflow)],
        offline=True,
    )
    assert context.history.consistency_status == RepositoryConsistencyStatus.CHANGED
    assert not report.is_complete


def test_state_markers_are_deterministic_and_bounded(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    extractor = RepositoryExtractor()
    first = extractor.capture_state_marker(tmp_path)
    second = extractor.capture_state_marker(tmp_path)
    assert first == second
    assert len(first.refs_digest) == 64
    assert len(first.git_dir_identity) == 64


def test_reference_marker_limit_propagates_incomplete_state(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    subprocess.run(
        ["git", "branch", "consistency-extra", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        shell=False,
    )
    report, context = run_analysis(
        parse_repository_input(str(tmp_path)),
        detectors=[],
        offline=True,
        security_limits=SecurityLimits(max_refs=1),
    )
    assert context.history.consistency_status == RepositoryConsistencyStatus.MARKER_TRUNCATED
    assert not report.is_complete


def test_history_extraction_uses_one_log_traversal_and_omits_bodies(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path, message="subject\n\nlarge body that detectors do not consume")
    runner = GitRunner()
    real_run = runner.run
    commands: list[list[str]] = []

    def recording_run(args, cwd=None, timeout=None, check=True):
        commands.append(args)
        return real_run(args, cwd=cwd, timeout=timeout, check=check)

    with patch.object(runner, "run", side_effect=recording_run):
        history = RepositoryExtractor(runner=runner).extract(parse_repository_input(str(tmp_path)))
    assert sum(command[0] == "log" for command in commands) == 1
    assert "--shortstat" in next(command for command in commands if command[0] == "log")
    assert history.commits[0].body == ""


def test_shared_summary_is_run_local_immutable_and_correct() -> None:
    base = datetime(2020, 1, 1, tzinfo=UTC)
    commits = [
        make_synthetic_commit(
            commit_hash=f"{index:040x}",
            parents=[] if index == 0 else [f"{index - 1:040x}"],
            author_email=f"user{index % 3}@example.com",
            author_date=base + timedelta(seconds=index),
            committer_date=base + timedelta(seconds=index),
            changed_files_count=index + 1,
        )
        for index in range(10)
    ]
    context = make_synthetic_context(commits)
    summary = build_analysis_summary(context)
    context.analysis_summary = summary
    assert len(summary.commit_by_hash) == 10
    assert len(summary.author_counts) == 3
    assert summary.total_changed_files == 55
    with pytest.raises(TypeError):
        summary.commit_by_hash["new"] = commits[0]  # type: ignore[index]


def test_large_synthetic_history_and_unique_intervals_remain_bounded() -> None:
    base = datetime(2020, 1, 1, tzinfo=UTC)
    elapsed = 0
    commits = []
    for index in range(10_000):
        elapsed += index + 1
        commits.append(
            make_synthetic_commit(
                commit_hash=f"{index:040x}",
                author_email=f"user{index}@example.com",
                author_date=base + timedelta(seconds=elapsed),
                committer_date=base + timedelta(seconds=elapsed),
            )
        )
    context = make_synthetic_context(commits)
    summary = get_analysis_summary(context)
    result = RegularIntervalsDetector().analyze(context)
    assert len(summary.author_counts) == 10_000
    assert len(summary.commits_by_author_date) == 10_000
    assert result.findings == []


def test_large_tag_index_is_deterministic() -> None:
    context = make_synthetic_context([make_synthetic_commit(commit_hash="a" * 40)])
    context.history.tags = [
        TagNode(
            ref_name=f"refs/tags/v{index}",
            short_name=f"v{index}",
            target_hash=f"{index:040x}",
            target_type="commit",
        )
        for index in range(5_000)
    ]
    first = build_analysis_summary(context)
    second = build_analysis_summary(context)
    assert tuple(first.tags_by_target) == tuple(second.tags_by_target)
    assert len(first.tags_by_name) == 5_000


def test_release_indexes_and_prefix_sums_are_reused_correctly() -> None:
    commits = [
        make_synthetic_commit(
            commit_hash=character * 40,
            changed_files_count=index + 1,
            insertions=(index + 1) * 10,
        )
        for index, character in enumerate(("c", "b", "a"))
    ]
    context = make_synthetic_context(commits)
    index = build_release_resolution_index(context.history)
    assert index.files_prefix == (0, 1, 3, 6)

    releases = [
        parse_release_from_api(
            {
                "id": release_id,
                "name": f"v{release_id}",
                "tag_name": f"v{release_id}",
                "target_commitish": target,
                "published_at": published,
                "assets": [],
            }
        )
        for release_id, target, published in (
            (1, "a" * 40, "2026-01-01T00:00:00Z"),
            (2, "c" * 40, "2026-02-01T00:00:00Z"),
        )
    ]
    result = run_release_analysis(releases, context.history, "o", "r")
    assert result.releases[1].files_changed_since_prev == 6
    assert result.releases[1].insertions_since_prev == 60


def test_api_rules_filter_avoids_unneeded_requests(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(500, json={})

    client = GitHubClient(transport=httpx.MockTransport(handler), max_retries=0)
    with patch("gitforensics.engine._extract_github_owner_repo", return_value=("o", "r")):
        report, _ = run_analysis(
            parse_repository_input(str(tmp_path)),
            rules_filter=["GF001"],
            github_client=client,
        )
    client.close()
    assert calls == []
    assert report.is_complete


def test_api_metadata_request_is_not_duplicated(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json={
                "id": 1,
                "owner": {"login": "o"},
                "name": "r",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "pushed_at": "2026-01-01T00:00:00Z",
            },
        )

    client = GitHubClient(transport=httpx.MockTransport(handler))
    with patch("gitforensics.engine._extract_github_owner_repo", return_value=("o", "r")):
        run_analysis(
            parse_repository_input(str(tmp_path)),
            rules_filter=["GF010"],
            github_client=client,
        )
    client.close()
    assert calls == 1


def test_api_pagination_stops_at_release_limit_and_preserves_items() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json=[{"id": 1}, {"id": 2}],
            headers={"Link": '<https://api.github.com/repos/o/r/releases?page=2>; rel="next"'},
        )

    client = GitHubClient(
        transport=httpx.MockTransport(handler),
        limits=SecurityLimits(max_releases=2),
    )
    result = client.get_releases_bounded("o", "r")
    client.close()
    assert len(result.items) == 2
    assert result.truncated
    assert calls == 1


def test_attestation_lookup_skips_network_without_valid_digest() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    release = parse_release_from_api(
        {
            "id": 1,
            "tag_name": "v1",
            "assets": [{"id": 2, "name": "a.zip", "digest": "invalid"}],
        }
    )
    state, *_rest = lookup_attestation(
        release.assets[0],
        "o",
        "r",
        httpx.MockTransport(handler),
        1.0,
        None,
        "https://api.github.com",
    )
    assert state == AttestationState.ATTESTATION_LOOKUP_UNAVAILABLE
    assert calls == 0


def test_disabled_asset_verification_performs_no_downloads() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    context = make_synthetic_context([make_synthetic_commit(commit_hash="a" * 40)])
    release = parse_release_from_api(
        {
            "id": 1,
            "tag_name": "v1",
            "target_commitish": "a" * 40,
            "published_at": "2026-01-01T00:00:00Z",
            "assets": [
                {
                    "id": 2,
                    "name": "a.zip",
                    "browser_download_url": "https://objects.githubusercontent.com/a.zip",
                }
            ],
        }
    )
    run_release_analysis(
        [release],
        context.history,
        "o",
        "r",
        verify_assets=False,
        transport=httpx.MockTransport(handler),
    )
    assert calls == 0


def test_sanitization_cycle_protection_and_bounded_nested_evidence() -> None:
    cyclic: dict[str, object] = {"secret": "token=abc123456789"}
    cyclic["self"] = cyclic
    cyclic["many"] = list(range(100))
    limits = SecurityLimits(max_evidence_items=5)
    sanitized = sanitize_value(cyclic, limits=limits)
    assert sanitized["self"] == "[CYCLE]"
    assert len(sanitized["many"]) == 6
    assert "abc123456789" not in json.dumps(sanitized)


def test_stable_fingerprint_scoring_json_and_terminal_ordering() -> None:
    findings = [
        Finding(
            rule_id,
            title,
            "description",
            Severity.MEDIUM,
            Confidence.HIGH,
            Evidence({"value": value}),
        )
        for rule_id, title, value in (("GF002", "b", 2), ("GF001", "a", 1))
    ]
    first_score = calculate_risk_score(findings)
    second_score = calculate_risk_score(list(reversed(findings)))
    assert first_score.to_dict() == second_score.to_dict()
    equivalent = Finding(
        "GF002",
        "b",
        "description",
        Severity.MEDIUM,
        Confidence.HIGH,
        Evidence({"value": 2}),
    )
    assert findings[0].fingerprint == equivalent.fingerprint

    report = AnalysisReport(
        scan_timestamp="2026-07-22T00:00:00Z",
        duration_seconds=1.0,
        findings=sorted(findings, key=lambda finding: finding.rule_id),
        risk_score=first_score.score,
        score_explanation=first_score.to_dict(),
    )
    first_json = render_report(report, OutputFormat.JSON)
    second_json = render_report(report, OutputFormat.JSON)
    assert first_json == second_json
    terminal = render_report(report, OutputFormat.TERMINAL, no_color=True)
    assert terminal.index("GF001") < terminal.index("GF002")


def test_detector_truncation_propagates_incomplete_state(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    report, _ = run_analysis(
        parse_repository_input(str(tmp_path)),
        detectors=[_TruncatingDetector()],
        offline=True,
    )
    assert not report.is_complete
    assert "Synthetic detector" in " ".join(report.incomplete_analysis_reasons)


def test_concurrent_independent_scans_do_not_share_state_or_environment(tmp_path: Path) -> None:
    original_environment = dict(os.environ)
    repositories = [tmp_path / "one", tmp_path / "two"]
    for index, repository in enumerate(repositories):
        create_dummy_repo(repository)
        add_commit(repository, message=f"repo-{index}")

    def scan(repository: Path):
        return run_analysis(
            parse_repository_input(str(repository)),
            detectors=[_SummaryIdentityDetector()],
            offline=True,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(scan, repositories))
    assert all(report.is_complete for report, _context in results)
    assert results[0][1].analysis_summary is not results[1][1].analysis_summary
    assert dict(os.environ) == original_environment


def test_concurrent_report_writes_to_different_files(tmp_path: Path) -> None:
    targets = [tmp_path / "one.json", tmp_path / "two.json"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(
            pool.map(
                lambda pair: write_report_to_file(pair[0], str(pair[1])),
                (("one", targets[0]), ("two", targets[1])),
            )
        )
    assert targets[0].read_text(encoding="utf-8") == "one"
    assert targets[1].read_text(encoding="utf-8") == "two"


def test_concurrent_same_report_path_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "same.json"
    entered_replace = threading.Event()
    release_replace = threading.Event()
    real_replace = os.replace

    def blocking_replace(source: str, destination: str) -> None:
        entered_replace.set()
        assert release_replace.wait(timeout=10)
        real_replace(source, destination)

    first_error: list[BaseException] = []

    def first_write() -> None:
        try:
            write_report_to_file("first", str(target), force=True)
        except BaseException as error:
            first_error.append(error)

    with patch("gitforensics.reporting.os.replace", side_effect=blocking_replace):
        thread = threading.Thread(target=first_write)
        thread.start()
        assert entered_replace.wait(timeout=10)
        with pytest.raises(OutputWriteError):
            write_report_to_file("second", str(target), force=True)
        release_replace.set()
        thread.join(timeout=10)
    assert first_error == []
    assert target.read_text(encoding="utf-8") == "first"


def test_engine_preserves_releases_and_marks_api_truncation(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    commit_hash = add_commit(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/contents/.github/workflows"):
            return httpx.Response(200, json=[])
        if request.url.path.endswith("/releases"):
            release = {
                "id": 1,
                "name": "v1",
                "tag_name": "v1",
                "target_commitish": commit_hash,
                "published_at": "2026-01-01T00:00:00Z",
                "assets": [
                    {"id": 1, "name": "one.zip"},
                    {"id": 2, "name": "two.zip"},
                ],
            }
            return httpx.Response(
                200,
                json=[release, {**release, "id": 2}],
                headers={"Link": '<https://api.github.com/repos/o/r/releases?page=2>; rel="next"'},
            )
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

    limits = SecurityLimits(max_releases=1, max_release_assets=1)
    client = GitHubClient(transport=httpx.MockTransport(handler), limits=limits)
    with patch("gitforensics.engine._extract_github_owner_repo", return_value=("o", "r")):
        report, context = run_analysis(
            parse_repository_input(str(tmp_path)),
            github_client=client,
            security_limits=limits,
        )
    client.close()
    assert report.total_releases == 1
    assert context.release_analysis_result is not None
    assert len(context.release_analysis_result.releases[0].release.assets) == 1
    assert not report.is_complete
    assert any("release" in reason.lower() for reason in report.incomplete_analysis_reasons)


def test_engine_consistency_check_failure_is_typed(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    with patch.object(
        RepositoryExtractor,
        "capture_state_marker",
        side_effect=OSError("state unavailable"),
    ):
        report, context = run_analysis(
            parse_repository_input(str(tmp_path)), detectors=[], offline=True
        )
    assert context.history.consistency_status == RepositoryConsistencyStatus.CHECK_FAILED
    assert not report.is_complete
    assert "state unavailable" not in json.dumps(report.to_dict())


def test_engine_stops_after_global_finding_limit(tmp_path: Path) -> None:
    create_dummy_repo(tmp_path)
    add_commit(tmp_path)
    finding = Finding(
        "GF-MANY",
        "many",
        "many",
        Severity.INFO,
        Confidence.HIGH,
        Evidence(),
    )
    first = MagicMock(spec=BaseDetector)
    first.get_rule_id.return_value = "GF-MANY"
    first.analyze.return_value = DetectorResult("GF-MANY", findings=[finding, finding])
    second = MagicMock(spec=BaseDetector)
    second.get_rule_id.return_value = "GF-LATE"
    report, _ = run_analysis(
        parse_repository_input(str(tmp_path)),
        detectors=[first, second],
        offline=True,
        security_limits=SecurityLimits(max_findings=1),
    )
    assert len(report.findings) == 1
    assert not report.is_complete
    second.analyze.assert_not_called()


def test_remote_workflow_limits_are_explicit_and_urls_deduplicated() -> None:
    downloads = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal downloads
        if request.url.host == "api.github.com":
            return httpx.Response(
                200,
                json=[
                    {
                        "type": "file",
                        "name": "large.yml",
                        "size": 100,
                        "download_url": "https://raw.githubusercontent.com/o/r/large.yml",
                    },
                    {
                        "type": "file",
                        "name": "one.yml",
                        "size": 5,
                        "download_url": "https://raw.githubusercontent.com/o/r/shared.yml",
                    },
                    {
                        "type": "file",
                        "name": "duplicate.yml",
                        "size": 5,
                        "download_url": "https://raw.githubusercontent.com/o/r/shared.yml",
                    },
                    {
                        "type": "file",
                        "name": "two.yml",
                        "size": 5,
                        "download_url": "https://raw.githubusercontent.com/o/r/two.yml",
                    },
                ],
            )
        downloads += 1
        return httpx.Response(200, content=b"x: 1")

    client = GitHubClient(
        transport=httpx.MockTransport(handler),
        limits=SecurityLimits(max_workflow_file_bytes=10, max_workflow_files=1),
    )
    result = client.get_workflow_files_bounded("o", "r")
    client.close()
    assert len(result.workflows) == 1
    assert downloads == 1
    assert len(result.incomplete_reasons) == 2


def test_permanent_github_server_response_is_not_retried() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(501)

    client = GitHubClient(transport=httpx.MockTransport(handler), max_retries=5)
    with pytest.raises(Exception, match="501"):
        client.get_repository_metadata("o", "r")
    client.close()
    assert calls == 1


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (
            httpx.Response(302, headers={"location": "https://api.github.com/next"}),
            AttestationState.ATTESTATION_LOOKUP_UNAVAILABLE,
        ),
        (httpx.Response(404), AttestationState.NO_ATTESTATION_FOUND),
        (httpx.Response(401), AttestationState.ATTESTATION_LOOKUP_UNAVAILABLE),
        (httpx.Response(500), AttestationState.ATTESTATION_LOOKUP_UNAVAILABLE),
        (httpx.Response(200, json=[]), AttestationState.ATTESTATION_RESPONSE_MALFORMED),
        (httpx.Response(200, json={"attestations": []}), AttestationState.NO_ATTESTATION_FOUND),
        (
            httpx.Response(200, json={"attestations": ["bad"]}),
            AttestationState.ATTESTATION_RESPONSE_MALFORMED,
        ),
        (
            httpx.Response(
                200,
                json={"attestations": [{"bundle": {"dsseEnvelope": {"payload": "not-base64"}}}]},
            ),
            AttestationState.ATTESTATION_RESPONSE_MALFORMED,
        ),
    ],
)
def test_attestation_failure_responses_are_typed(
    response: httpx.Response, expected: AttestationState
) -> None:
    digest = "a" * 64
    release = parse_release_from_api(
        {
            "id": 1,
            "tag_name": "v1",
            "assets": [{"id": 1, "name": "a.zip", "digest": f"sha256:{digest}"}],
        }
    )
    transport = httpx.MockTransport(lambda request: response)
    state, *_rest = lookup_attestation(
        release.assets[0], "o", "r", transport, 1.0, None, "https://api.github.com"
    )
    assert state == expected


def test_asset_redirect_and_response_limits_are_typed() -> None:
    release = parse_release_from_api(
        {
            "id": 1,
            "tag_name": "v1",
            "assets": [
                {
                    "id": 1,
                    "name": "a.zip",
                    "size": 0,
                    "browser_download_url": "https://objects.githubusercontent.com/a.zip",
                }
            ],
        }
    )
    asset = release.assets[0]
    from gitforensics.release_analysis import verify_asset_digest

    missing_location = httpx.MockTransport(lambda request: httpx.Response(302))
    verified = verify_asset_digest(
        asset,
        missing_location,
        1.0,
        AssetVerificationConfig(),
        [0],
        [0],
    )
    assert verified.digest_state == DigestState.DOWNLOAD_FAILED

    asset.digest_state = DigestState.DIGEST_MISSING
    oversized = httpx.MockTransport(
        lambda request: httpx.Response(200, headers={"content-length": "11"}, content=b"")
    )
    verified = verify_asset_digest(
        asset,
        oversized,
        1.0,
        AssetVerificationConfig(max_asset_size_bytes=10),
        [0],
        [0],
    )
    assert verified.digest_state == DigestState.VERIFICATION_SKIPPED


def test_release_verification_budget_stops_additional_downloads() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if "/attestations/" in request.url.path:
            return httpx.Response(404)
        return httpx.Response(200, content=b"asset")

    context = make_synthetic_context([make_synthetic_commit(commit_hash="a" * 40)])
    release = parse_release_from_api(
        {
            "id": 1,
            "tag_name": "v1",
            "target_commitish": "a" * 40,
            "published_at": "2026-01-01T00:00:00Z",
            "assets": [
                {
                    "id": index,
                    "name": f"asset-{index}.zip",
                    "browser_download_url": (
                        f"https://objects.githubusercontent.com/asset-{index}.zip"
                    ),
                }
                for index in range(2)
            ],
        }
    )
    result = run_release_analysis(
        [release],
        context.history,
        "o",
        "r",
        verify_assets=True,
        asset_config=AssetVerificationConfig(max_asset_count=1),
        transport=httpx.MockTransport(handler),
    )
    assert result.incomplete
    assert sum("objects.githubusercontent.com" in call for call in calls) == 1


def test_sanitizer_handles_hostile_objects_sets_depth_and_limit_validation() -> None:
    class Hostile:
        def __str__(self) -> str:
            raise RuntimeError("str blocked")

        def __repr__(self) -> str:
            raise RuntimeError("repr blocked")

    hostile = Hostile()
    sanitized = sanitize_value({hostile, "safe"}, limits=SecurityLimits(max_evidence_items=1))
    assert isinstance(sanitized, list)
    assert "Hostile" in json.dumps(sanitize_value(hostile))
    nested: object = "end"
    for _index in range(8):
        nested = [nested]
    assert "TRUNCATED" in json.dumps(sanitize_value(nested))
    assert "example.com:8443/path" in sanitize_text("https://example.com:8443/path?token=x")

    with pytest.raises(ValueError):
        SecurityLimits(max_commits=10_000_001).validate()
    with pytest.raises(ValueError):
        SecurityLimits(max_refs=1_000_001).validate()
    with pytest.raises(ValueError):
        replace(SecurityLimits(), max_git_stdout_bytes=1024**3 + 1).validate()


def test_report_write_failure_cleans_temp_and_reservation(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    with patch("gitforensics.reporting.os.replace", side_effect=OSError("replace failed")):
        with pytest.raises(OutputWriteError):
            write_report_to_file("content", str(target), force=True)
    assert not list(tmp_path.glob(".gitforensics_report_*"))
    assert not list(tmp_path.glob("*.gitforensics.lock"))
