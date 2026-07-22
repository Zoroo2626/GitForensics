"""Deterministic micro-benchmark and bounded stress workloads."""

from __future__ import annotations

import argparse
import gc
import json
import os
import subprocess
import sys
import tempfile
import time
import tracemalloc
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from gitforensics.analysis_summary import build_analysis_summary  # noqa: E402
from gitforensics.compat import UTC  # noqa: E402
from gitforensics.detectors import get_default_detectors  # noqa: E402
from gitforensics.detectors.local.regular_intervals import (  # noqa: E402
    RegularIntervalsDetector,
)
from gitforensics.detectors.local.tag_anomalies import TagAnomaliesDetector  # noqa: E402
from gitforensics.git import RepositoryExtractor, parse_repository_input  # noqa: E402
from gitforensics.models import (  # noqa: E402
    AnalysisReport,
    CommitNode,
    Confidence,
    Evidence,
    ExtractedHistory,
    Finding,
    OutputFormat,
    RepositoryContext,
    RepositoryInput,
    RepositoryInputType,
    Severity,
    SignatureStatus,
    TagNode,
)
from gitforensics.release_analysis import (  # noqa: E402
    parse_release_from_api,
    run_release_analysis,
)
from gitforensics.reporting import render_report  # noqa: E402
from gitforensics.scoring import calculate_risk_score  # noqa: E402
from gitforensics.security import SecurityLimits  # noqa: E402


def _measure(label: str, action: Callable[[], Any]) -> dict[str, Any]:
    gc.collect()
    tracemalloc.start()
    started = time.perf_counter()
    result = action()
    duration = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    del result
    return {
        "label": label,
        "duration_seconds": round(duration, 6),
        "peak_python_mib": round(peak / (1024 * 1024), 3),
    }


def _commits(
    count: int,
    *,
    contributors: int = 10,
    unique_intervals: bool = False,
) -> list[CommitNode]:
    base = datetime(2020, 1, 1, tzinfo=UTC)
    timestamp = base
    commits: list[CommitNode] = []
    for index in range(count):
        timestamp += timedelta(seconds=(index + 1 if unique_intervals else 60))
        commit_hash = f"{index + 1:040x}"
        commits.append(
            CommitNode(
                hash=commit_hash,
                parents=[] if index == 0 else [f"{index:040x}"],
                author_name=f"Contributor {index % contributors}",
                author_email=f"user{index % contributors}@example.com",
                author_date=timestamp,
                committer_name=f"Contributor {index % contributors}",
                committer_email=f"user{index % contributors}@example.com",
                committer_date=timestamp,
                subject=f"Synthetic commit {index}",
                body="",
                tree_hash=f"{count + index + 1:040x}",
                changed_files_count=(index % 7) + 1,
                insertions=(index % 13) + 1,
                deletions=index % 5,
                signature_status=SignatureStatus.UNSIGNED,
            )
        )
    commits.reverse()
    return commits


def _context(commits: list[CommitNode], tags: list[TagNode] | None = None) -> RepositoryContext:
    repository_input = RepositoryInput(
        raw_input="<SYNTHETIC>",
        input_type=RepositoryInputType.LOCAL,
        resolved_path_or_url="<SYNTHETIC>",
    )
    history = ExtractedHistory(
        repository_path="<SYNTHETIC>",
        git_dir=".git",
        is_bare=False,
        head_commit=commits[0].hash if commits else None,
        commits=commits,
        tags=tags or [],
    )
    return RepositoryContext(input=repository_input, history=history, offline=True)


def _fast_import_repository(path: Path, commit_count: int) -> None:
    subprocess.run(
        ["git", "init", "--quiet", str(path)],
        check=True,
        capture_output=True,
        shell=False,
    )
    commands: list[str] = []
    for index in range(1, commit_count + 1):
        commands.extend(
            [
                "commit refs/heads/main",
                f"mark :{index}",
                f"author Benchmark <bench@example.com> {1_600_000_000 + index} +0000",
                f"committer Benchmark <bench@example.com> {1_600_000_000 + index} +0000",
                f"data {len(str(index))}",
                str(index),
            ]
        )
        if index > 1:
            commands.append(f"from :{index - 1}")
        commands.append("")
    payload = "\n".join(commands).encode("utf-8")
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC"}
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    subprocess.run(
        ["git", "fast-import", "--quiet"],
        cwd=path,
        input=payload,
        check=True,
        capture_output=True,
        env=environment,
        shell=False,
    )
    subprocess.run(
        ["git", "symbolic-ref", "HEAD", "refs/heads/main"],
        cwd=path,
        check=True,
        capture_output=True,
        env=environment,
        shell=False,
    )


def _benchmark_real_extraction(commit_count: int) -> None:
    with tempfile.TemporaryDirectory(prefix="gitforensics_benchmark_") as temporary:
        repository = Path(temporary) / "repository"
        _fast_import_repository(repository, commit_count)
        history = RepositoryExtractor().extract(parse_repository_input(str(repository)))
        if len(history.commits) != commit_count:
            raise RuntimeError("Synthetic Git extraction returned an unexpected commit count.")


def _release_workload(history: ExtractedHistory, limits: SecurityLimits) -> None:
    releases = []
    asset_id = 0
    for release_id in range(limits.max_releases):
        assets = []
        asset_target = limits.max_release_assets * (release_id + 1) // limits.max_releases
        asset_start = limits.max_release_assets * release_id // limits.max_releases
        for _index in range(asset_start, asset_target):
            asset_id += 1
            assets.append(
                {
                    "id": asset_id,
                    "name": f"asset-{asset_id}.zip",
                    "size": 1_024,
                    "content_type": "application/zip",
                    "created_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-01T00:00:00Z",
                    "browser_download_url": (
                        f"https://objects.githubusercontent.com/assets/{asset_id}.zip"
                    ),
                }
            )
        target = history.commits[release_id % len(history.commits)].hash
        releases.append(
            parse_release_from_api(
                {
                    "id": release_id + 1,
                    "name": f"v1.{release_id}.0",
                    "tag_name": f"v1.{release_id}.0",
                    "target_commitish": target,
                    "published_at": (
                        datetime(2020, 1, 1, tzinfo=UTC) + timedelta(days=release_id)
                    ).isoformat(),
                    "assets": assets,
                },
                limits=limits,
            )
        )
    result = run_release_analysis(
        releases,
        history,
        owner="benchmark",
        repo="repository",
        verify_assets=False,
        limits=limits,
    )
    result.to_dict()


def _max_findings(limits: SecurityLimits) -> list[Finding]:
    evidence_values = ["x" * limits.max_evidence_string_chars] * limits.max_evidence_items
    return [
        Finding(
            rule_id=f"GF-BENCH-{index:04d}",
            title=f"Finding {index}",
            description="Deterministic benchmark finding",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            evidence=Evidence({"items": evidence_values, "index": index}),
        )
        for index in range(limits.max_findings)
    ]


def run(profile: str) -> dict[str, Any]:
    limits = SecurityLimits()
    measurements: list[dict[str, Any]] = []
    model_sizes = (1, 100, 1_000, 10_000, limits.max_commits)
    for size in model_sizes:
        commits = _commits(size, contributors=min(size, 1_000))
        context = _context(commits)
        measurements.append(
            _measure(
                f"shared_summary_{size}_commits",
                lambda context=context: build_analysis_summary(context),
            )
        )

    detector_commits = _commits(10_000, contributors=2_000)
    detector_context = _context(detector_commits)
    detector_context.analysis_summary = build_analysis_summary(detector_context)

    def run_detectors() -> None:
        for detector in get_default_detectors():
            detector.analyze(detector_context)

    measurements.append(_measure("all_detectors_10000_commits", run_detectors))

    unique_context = _context(_commits(10_000, contributors=100, unique_intervals=True))
    measurements.append(
        _measure(
            "regular_intervals_10000_unique_values",
            lambda: RegularIntervalsDetector().analyze(unique_context),
        )
    )

    tag_context = _context(
        detector_commits,
        [
            TagNode(
                ref_name=f"refs/tags/v{index}",
                short_name=f"v{index}",
                target_hash=detector_commits[index].hash,
                target_type="commit",
            )
            for index in range(limits.max_tags)
        ],
    )
    tag_context.analysis_summary = build_analysis_summary(tag_context)
    measurements.append(
        _measure("tag_detector_10000_tags", lambda: TagAnomaliesDetector().analyze(tag_context))
    )

    measurements.append(
        _measure(
            "release_analysis_2000_releases_5000_assets",
            lambda: _release_workload(detector_context.history, limits),
        )
    )

    findings = _max_findings(limits)
    measurements.append(_measure("scoring_2000_findings", lambda: calculate_risk_score(findings)))
    report = AnalysisReport(
        repository="<SYNTHETIC>",
        scan_timestamp="2026-07-22T00:00:00Z",
        duration_seconds=1.0,
        findings=findings,
        security_limits=limits,
    )
    measurements.append(
        _measure(
            "json_report_max_findings_evidence",
            lambda: render_report(report, OutputFormat.JSON),
        )
    )

    real_sizes = (1, 100, 1_000) if profile == "full" else (1, 100)
    for size in real_sizes:
        measurements.append(
            _measure(
                f"real_git_extraction_{size}_commits",
                lambda size=size: _benchmark_real_extraction(size),
            )
        )

    return {
        "benchmark": "GitForensics Performance Benchmark",
        "profile": profile,
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "limits": {
            "commits": limits.max_commits,
            "tags": limits.max_tags,
            "releases": limits.max_releases,
            "release_assets": limits.max_release_assets,
            "findings": limits.max_findings,
            "evidence_items": limits.max_evidence_items,
        },
        "measurements": measurements,
        "memory_note": "Python peak excludes memory allocated inside Git subprocesses.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=("standard", "full"), default="full")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    results = run(args.profile)
    serialized = json.dumps(results, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(serialized + "\n", encoding="utf-8")
    print(serialized)


if __name__ == "__main__":
    main()
