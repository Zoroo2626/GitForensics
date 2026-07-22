"""GF009: Tag creation anomalies detector."""

import re

from gitforensics.analysis_summary import get_analysis_summary
from gitforensics.detectors.base import BaseDetector
from gitforensics.models import (
    Confidence,
    DetectorResult,
    Evidence,
    Finding,
    RepositoryContext,
    Severity,
)

SAME_COMMIT_TAG_THRESHOLD: int = 5
TAG_BURST_THRESHOLD: int = 10
TAGGER_DATE_MISMATCH_TOLERANCE_SECONDS: int = 86400

SEMVER_PATTERN = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")


def parse_semver(name: str) -> tuple[int, int, int] | None:
    """Parses a tag short name into a numeric (major, minor, patch) tuple if valid."""
    match = SEMVER_PATTERN.match(name)
    if match:
        return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    return None


class TagAnomaliesDetector(BaseDetector):
    """Detects tag creation anomalies including bulk tags and timestamp paradoxes."""

    def __init__(
        self,
        same_commit_threshold: int = SAME_COMMIT_TAG_THRESHOLD,
        burst_threshold: int = TAG_BURST_THRESHOLD,
        tagger_tolerance: int = TAGGER_DATE_MISMATCH_TOLERANCE_SECONDS,
    ) -> None:
        self.same_commit_threshold = same_commit_threshold
        self.burst_threshold = burst_threshold
        self.tagger_tolerance = tagger_tolerance

    def get_rule_id(self) -> str:
        return "GF009"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        tags = context.history.tags
        if not tags:
            return DetectorResult(
                rule_id=self.get_rule_id(),
                skipped=True,
                skip_reason="No tags found in repository.",
            )

        findings: list[Finding] = []

        # 1. Bulk tags targeting the same commit
        commit_to_tags = get_analysis_summary(context).tags_by_target

        for target_hash, target_tags in commit_to_tags.items():
            if len(target_tags) >= self.same_commit_threshold:
                evidence = Evidence(
                    data={
                        "anomaly_type": "bulk_tags_same_commit",
                        "target_hash": target_hash,
                        "affected_tags_count": len(target_tags),
                        "tag_names": [
                            tag.short_name
                            for tag in target_tags[: context.security_limits.max_evidence_items]
                        ],
                        "unique_target_commits_count": 1,
                        "threshold_crossed": self.same_commit_threshold,
                    }
                )
                findings.append(
                    Finding(
                        rule_id=self.get_rule_id(),
                        title="Multiple Tags Targeting Single Commit",
                        description=(
                            f"Found {len(target_tags)} tags targeting the exact same "
                            f"commit {target_hash[:8]}."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        evidence=evidence,
                    )
                )
                if len(findings) >= context.security_limits.max_findings:
                    return DetectorResult(
                        rule_id=self.get_rule_id(),
                        findings=findings,
                        truncated=True,
                        truncation_reason="GF009 findings reached the configured limit.",
                    )

        # 2. Tagger date vs commit date paradox
        for t in tags:
            if t.tagger_date and t.commit_date:
                diff = int((t.tagger_date - t.commit_date).total_seconds())
                if abs(diff) > self.tagger_tolerance:
                    evidence = Evidence(
                        data={
                            "anomaly_type": "tagger_date_mismatch",
                            "tag_name": t.short_name,
                            "target_hash": t.target_hash,
                            "tagger_timestamp": t.tagger_date.isoformat(),
                            "commit_timestamp": t.commit_date.isoformat(),
                            "calculated_difference_seconds": diff,
                            "allowed_tolerance_seconds": self.tagger_tolerance,
                        }
                    )
                    findings.append(
                        Finding(
                            rule_id=self.get_rule_id(),
                            title="Tagger Date Mismatch With Commit",
                            description=(
                                f"Tag '{t.short_name}' tagger date ({t.tagger_date.isoformat()}) "
                                f"differs from target commit by {abs(diff)}s."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            evidence=evidence,
                        )
                    )
                    if len(findings) >= context.security_limits.max_findings:
                        return DetectorResult(
                            rule_id=self.get_rule_id(),
                            findings=findings,
                            truncated=True,
                            truncation_reason="GF009 findings reached the configured limit.",
                        )

        # 3. SemVer vs Commit Date chronology conflict
        semver_tags = []
        for t in tags:
            ver = parse_semver(t.short_name)
            if ver and t.commit_date:
                semver_tags.append((ver, t))

        semver_tags.sort(key=lambda x: x[0])
        for i in range(1, len(semver_tags)):
            prev_ver, prev_tag = semver_tags[i - 1]
            curr_ver, curr_tag = semver_tags[i]
            if curr_tag.commit_date and prev_tag.commit_date:
                if (prev_tag.commit_date - curr_tag.commit_date).total_seconds() > 60:
                    evidence = Evidence(
                        data={
                            "anomaly_type": "semver_chronology_conflict",
                            "older_version_tag": prev_tag.short_name,
                            "older_version_commit_date": prev_tag.commit_date.isoformat(),
                            "newer_version_tag": curr_tag.short_name,
                            "newer_version_commit_date": curr_tag.commit_date.isoformat(),
                        }
                    )
                    findings.append(
                        Finding(
                            rule_id=self.get_rule_id(),
                            title="SemVer Order Conflicts With Commit Chronology",
                            description=(
                                f"Tag '{curr_tag.short_name}' is newer than "
                                f"'{prev_tag.short_name}' but its commit is older."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            evidence=evidence,
                        )
                    )
                    if len(findings) >= context.security_limits.max_findings:
                        return DetectorResult(
                            rule_id=self.get_rule_id(),
                            findings=findings,
                            truncated=True,
                            truncation_reason="GF009 findings reached the configured limit.",
                        )

        return DetectorResult(rule_id=self.get_rule_id(), findings=findings)
