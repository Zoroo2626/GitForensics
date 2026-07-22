"""Core orchestration engine for running detectors against repository context."""

import logging
import time
from collections.abc import Callable, Sequence
from datetime import datetime

import httpx

from gitforensics.analysis_summary import build_analysis_summary
from gitforensics.compat import UTC
from gitforensics.detectors import get_default_detectors
from gitforensics.detectors.base import BaseDetector
from gitforensics.errors import NetworkError
from gitforensics.git import RepositoryExtractor
from gitforensics.github import GitHubClient
from gitforensics.models import (
    AnalysisReport,
    Finding,
    GitHubMetadata,
    RepositoryConsistencyStatus,
    RepositoryContext,
    RepositoryInput,
)
from gitforensics.release_analysis import parse_release_from_api, run_release_analysis
from gitforensics.release_models import AssetVerificationConfig, ReleaseAnalysisResult
from gitforensics.scoring import calculate_risk_score, finding_sort_key
from gitforensics.security import SecurityLimits, sanitize_text

logger = logging.getLogger(__name__)


def run_analysis(
    repo_input: RepositoryInput,
    detectors: Sequence[BaseDetector] | None = None,
    rules_filter: list[str] | None = None,
    github_token: str | None = None,
    offline: bool = False,
    github_api_url: str = "https://api.github.com",
    github_client: GitHubClient | None = None,
    clock: Callable[[], datetime] | None = None,
    timer: Callable[[], float] | None = None,
    verify_assets: bool = False,
    asset_config: AssetVerificationConfig | None = None,
    asset_transport: httpx.BaseTransport | None = None,
    network_timeout: float = 10.0,
    security_limits: SecurityLimits | None = None,
) -> tuple[AnalysisReport, RepositoryContext]:
    """Executes history extraction and runs registered detectors against repository context."""
    get_time = timer or time.monotonic
    start_time = get_time()

    now_dt = (clock() if clock else datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")

    limits = security_limits or SecurityLimits()
    limits.validate()
    extractor = RepositoryExtractor(limits=limits)
    history = extractor.extract(repo_input)

    active_detectors = list(detectors if detectors is not None else get_default_detectors())
    if rules_filter:
        requested_rules = frozenset(rules_filter)
        active_detectors = [
            detector
            for detector in active_detectors
            if _safe_detector_id(detector) in requested_rules
        ]
    active_rule_ids = frozenset(_safe_detector_id(detector) for detector in active_detectors)

    github_metadata: GitHubMetadata | None = None
    incomplete_reasons: list[str] = list(history.warnings)
    if history.is_limited:
        incomplete_reasons.append(history.limit_reason)
    release_analysis_result: ReleaseAnalysisResult | None = None

    owner: str | None = None
    repo: str | None = None

    # Optional GitHub API enrichment
    if not offline:
        owner, repo = _extract_github_owner_repo(repo_input)
        if owner and repo:
            client: GitHubClient | None = None
            try:
                client = github_client or GitHubClient(
                    token=github_token,
                    base_url=github_api_url,
                    timeout=network_timeout,
                    limits=limits,
                )
                if "GF010" in active_rule_ids:
                    try:
                        github_metadata = client.get_repository_metadata(owner, repo)
                    except NetworkError as err:
                        msg = "GitHub repository metadata skipped: " + sanitize_text(
                            str(err), secrets=(github_token,)
                        )
                        logger.warning(msg)
                        incomplete_reasons.append(msg)
                if "GF008" in active_rule_ids and not history.workflows:
                    try:
                        workflow_result = client.get_workflow_files_bounded(owner, repo)
                        if workflow_result.workflows:
                            history.workflows.extend(workflow_result.workflows)
                        incomplete_reasons.extend(workflow_result.incomplete_reasons)
                    except NetworkError as err:
                        msg = "GitHub workflow enrichment skipped: " + sanitize_text(
                            str(err), secrets=(github_token,)
                        )
                        logger.warning(msg)
                        incomplete_reasons.append(msg)

                # Fetch releases
                if active_rule_ids.intersection(
                    {"GF011", "GF012", "GF013", "GF014", "GF015", "GF016"}
                ):
                    try:
                        release_collection = client.get_releases_bounded(owner, repo)
                        releases = []
                        asset_count = 0
                        asset_limit_recorded = False
                        for raw_release in release_collection.items:
                            remaining = max(0, limits.max_release_assets - asset_count)
                            raw_assets = raw_release.get("assets")
                            raw_asset_count = len(raw_assets) if isinstance(raw_assets, list) else 0
                            release = parse_release_from_api(
                                raw_release,
                                limits=limits,
                                asset_limit=remaining,
                            )
                            releases.append(release)
                            if raw_asset_count > remaining and not asset_limit_recorded:
                                incomplete_reasons.append(
                                    "Release asset analysis reached the configured asset limit."
                                )
                                asset_limit_recorded = True
                            asset_count += len(release.assets)
                        if release_collection.truncated:
                            incomplete_reasons.append(release_collection.truncation_reason)
                        default_branch = (
                            github_metadata.default_branch if github_metadata else "main"
                        )
                        release_analysis_result = run_release_analysis(
                            releases=releases,
                            history=history,
                            owner=owner,
                            repo=repo,
                            default_branch=default_branch,
                            verify_assets=verify_assets and not release_collection.truncated,
                            asset_config=asset_config,
                            transport=asset_transport,
                            timeout=network_timeout,
                            token=github_token,
                            api_base_url=github_api_url,
                            limits=limits,
                        )
                        if release_collection.truncated:
                            release_analysis_result.incomplete = True
                            release_analysis_result.incomplete_reasons.append(
                                release_collection.truncation_reason
                            )
                        if release_analysis_result.incomplete:
                            incomplete_reasons.extend(release_analysis_result.incomplete_reasons)
                    except NetworkError as err:
                        msg = "Release API request skipped: " + sanitize_text(
                            str(err), secrets=(github_token,)
                        )
                        logger.warning(msg)
                        incomplete_reasons.append(msg)
                    except Exception as err:
                        msg = "Unexpected error during release analysis: " + sanitize_text(
                            str(err), secrets=(github_token,)
                        )
                        logger.warning(msg)
                        incomplete_reasons.append(msg)

            except NetworkError as err:
                msg = "GitHub API enrichment skipped: " + sanitize_text(
                    str(err), secrets=(github_token,)
                )
                logger.warning(msg)
                incomplete_reasons.append(msg)
            except Exception as err:
                msg = "Unexpected error during GitHub API enrichment: " + sanitize_text(
                    str(err), secrets=(github_token,)
                )
                logger.warning(msg)
                incomplete_reasons.append(msg)
            finally:
                if github_client is None and client is not None:
                    client.close()

    context = RepositoryContext(
        input=repo_input,
        history=history,
        github_token=None,
        github_metadata=github_metadata,
        offline=offline,
        release_analysis_result=release_analysis_result,
        security_limits=limits,
    )
    context.analysis_summary = build_analysis_summary(context)

    all_findings: list[Finding] = []
    skipped_detectors: list[str] = []
    failed_detectors: list[str] = []

    for detector_index, detector in enumerate(active_detectors):
        detector_id = _safe_detector_id(detector)
        try:
            res = detector.analyze(context)
            if res.skipped:
                skipped_detectors.append(detector_id)
            elif res.findings:
                remaining = limits.max_findings - len(all_findings)
                all_findings.extend(res.findings[: max(0, remaining)])
                if len(res.findings) > remaining:
                    incomplete_reasons.append(
                        f"Detector {detector_id} findings reached the configured report limit."
                    )
                    if remaining <= 0:
                        break
                if res.truncated:
                    incomplete_reasons.append(
                        res.truncation_reason
                        or f"Detector {detector_id} reached its configured finding limit."
                    )
                if len(all_findings) >= limits.max_findings and detector_index + 1 < len(
                    active_detectors
                ):
                    incomplete_reasons.append(
                        "Finding limit reached before all selected detectors could run."
                    )
                    break
        except Exception as err:
            safe_error = sanitize_text(str(err), secrets=(github_token,))
            logger.error(
                "Detector %s failed during execution: %s",
                detector_id,
                safe_error,
            )
            failed_detectors.append(detector_id)
            incomplete_reasons.append(f"Detector {detector_id} execution error: {safe_error}")

    if repo_input.input_type.value == "local":
        start_marker = history.state_marker_start
        if start_marker is None:
            history.consistency_status = RepositoryConsistencyStatus.CHECK_FAILED
            incomplete_reasons.append(
                "Repository consistency could not be verified for the completed scan."
            )
        else:
            try:
                end_marker = extractor.capture_state_marker(repo_input.resolved_path_or_url)
            except Exception as err:
                history.consistency_status = RepositoryConsistencyStatus.CHECK_FAILED
                logger.warning(
                    "Repository consistency check failed: %s",
                    sanitize_text(str(err), secrets=(github_token,)),
                )
                incomplete_reasons.append(
                    "Repository consistency could not be verified for the completed scan."
                )
            else:
                if (
                    start_marker.refs_truncated
                    or end_marker.refs_truncated
                    or start_marker.workflows_truncated
                    or end_marker.workflows_truncated
                ):
                    history.consistency_status = RepositoryConsistencyStatus.MARKER_TRUNCATED
                    incomplete_reasons.append(
                        "Repository consistency marker reached the configured reference limit."
                    )
                elif start_marker != end_marker:
                    history.consistency_status = RepositoryConsistencyStatus.CHANGED
                    incomplete_reasons.append(
                        "Repository state changed during analysis; results are not a stable "
                        "snapshot."
                    )
                else:
                    history.consistency_status = RepositoryConsistencyStatus.STABLE

    deduped_findings = _deduplicate_findings(all_findings)
    sorted_findings = _sort_findings_deterministically(deduped_findings)

    is_complete = len(failed_detectors) == 0 and len(incomplete_reasons) == 0
    score_exp = calculate_risk_score(sorted_findings, is_complete=is_complete)

    # Unique contributors count
    summary = context.analysis_summary
    assert summary is not None

    elapsed = max(0.0, get_time() - start_time)

    total_releases = release_analysis_result.total_releases if release_analysis_result else 0
    release_analysis_dict = release_analysis_result.to_dict() if release_analysis_result else None

    report = AnalysisReport(
        schema_version="1.0.0",
        repository=repo_input.raw_input,
        input_type=repo_input.input_type.value,
        scan_timestamp=now_dt,
        duration_seconds=elapsed,
        head_commit=history.head_commit,
        total_commits=len(history.commits),
        total_contributors=len(summary.author_counts),
        total_tags=len(history.tags),
        total_workflows=len(history.workflows),
        github_metadata_available=github_metadata is not None,
        is_complete=is_complete,
        assessment_label=score_exp.assessment_label,
        risk_score=score_exp.score,
        score_explanation=score_exp.to_dict(),
        findings=sorted_findings,
        skipped_detectors=sorted(set(skipped_detectors)),
        failed_detectors=sorted(set(failed_detectors)),
        incomplete_analysis_reasons=sorted(set(incomplete_reasons)),
        total_releases=total_releases,
        release_analysis=release_analysis_dict,
        security_limits=limits,
    )

    return report, context


def _safe_detector_id(detector: BaseDetector) -> str:
    """Obtain a bounded identifier even when a third-party detector is malformed."""
    try:
        value = detector.get_rule_id()
    except Exception:
        value = detector.__class__.__name__
    return sanitize_text(str(value), max_chars=32, minimize_emails=False)


def _extract_github_owner_repo(repo_input: RepositoryInput) -> tuple[str | None, str | None]:
    """Parses owner and repo from raw input or resolved URL."""
    match = __import__("re").fullmatch(
        r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?",
        repo_input.resolved_path_or_url,
    )
    if match:
        return match.group(1), match.group(2)
    return None, None


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Removes exact duplicate findings deterministically."""
    seen: set[str] = set()
    unique: list[Finding] = []

    for f in findings:
        rep_hash = (
            f.evidence.data.get("commit_hash")
            or f.evidence.data.get("root_commit_hash")
            or f.evidence.data.get("workflow_path")
        )
        key = f"{f.rule_id}|{f.title}|{f.description}|{rep_hash}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def _sort_findings_deterministically(findings: list[Finding]) -> list[Finding]:
    """Sorts findings deterministically by rule_id, severity rank, and title."""
    return sorted(findings, key=finding_sort_key)
