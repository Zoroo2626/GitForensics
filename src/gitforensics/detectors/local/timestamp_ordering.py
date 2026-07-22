"""GF006: Timestamp ordering anomalies detector."""

from datetime import datetime

from gitforensics.analysis_summary import get_analysis_summary
from gitforensics.compat import UTC
from gitforensics.detectors.base import BaseDetector
from gitforensics.models import (
    Confidence,
    DetectorResult,
    Evidence,
    Finding,
    RepositoryContext,
    Severity,
)

AUTHOR_AFTER_COMMITTER_TOLERANCE_SECONDS: int = 60
CHILD_PREDATES_PARENT_TOLERANCE_SECONDS: int = 60
FUTURE_COMMIT_TOLERANCE_SECONDS: int = 86400


class TimestampOrderingDetector(BaseDetector):
    """Detects timestamp paradoxes in commits, parent-child relationships, and future dates."""

    def __init__(
        self,
        analysis_clock: datetime | None = None,
        author_after_tolerance: int = AUTHOR_AFTER_COMMITTER_TOLERANCE_SECONDS,
        child_predates_tolerance: int = CHILD_PREDATES_PARENT_TOLERANCE_SECONDS,
        future_tolerance: int = FUTURE_COMMIT_TOLERANCE_SECONDS,
    ) -> None:
        self.analysis_clock = analysis_clock
        self.author_after_tolerance = author_after_tolerance
        self.child_predates_tolerance = child_predates_tolerance
        self.future_tolerance = future_tolerance

    def get_rule_id(self) -> str:
        return "GF006"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        commits = context.history.commits
        if not commits:
            return DetectorResult(rule_id=self.get_rule_id(), findings=[])

        now = self.analysis_clock or datetime.now(UTC)
        commit_map = get_analysis_summary(context).commit_by_hash
        findings: list[Finding] = []
        max_findings = context.security_limits.max_findings

        for c in commits:
            # 1. Author timestamp after committer timestamp
            diff_author_committer = int((c.author_date - c.committer_date).total_seconds())
            if diff_author_committer > self.author_after_tolerance:
                evidence = Evidence(
                    data={
                        "anomaly_type": "author_after_committer",
                        "commit_hash": c.hash,
                        "author_timestamp": c.author_date.isoformat(),
                        "committer_timestamp": c.committer_date.isoformat(),
                        "calculated_difference_seconds": diff_author_committer,
                        "allowed_tolerance_seconds": self.author_after_tolerance,
                    }
                )
                findings.append(
                    Finding(
                        rule_id=self.get_rule_id(),
                        title="Author Date Later Than Committer Date",
                        description=(
                            f"Commit {c.hash[:8]} has author date ({c.author_date.isoformat()}) "
                            f"which is {diff_author_committer}s later than committer date."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        evidence=evidence,
                    )
                )
                if len(findings) >= max_findings:
                    return DetectorResult(
                        rule_id=self.get_rule_id(),
                        findings=findings,
                        truncated=True,
                        truncation_reason="GF006 findings reached the configured limit.",
                    )

            # 2. Child commit timestamped earlier than parent commit
            for p_hash in c.parents:
                parent = commit_map.get(p_hash)
                if parent:
                    diff_child_parent = int(
                        (parent.committer_date - c.committer_date).total_seconds()
                    )
                    if diff_child_parent > self.child_predates_tolerance:
                        evidence = Evidence(
                            data={
                                "anomaly_type": "child_predates_parent",
                                "commit_hash": c.hash,
                                "parent_hash": p_hash,
                                "child_committer_timestamp": c.committer_date.isoformat(),
                                "parent_committer_timestamp": parent.committer_date.isoformat(),
                                "calculated_difference_seconds": diff_child_parent,
                                "allowed_tolerance_seconds": self.child_predates_tolerance,
                            }
                        )
                        findings.append(
                            Finding(
                                rule_id=self.get_rule_id(),
                                title="Child Commit Predates Parent",
                                description=(
                                    f"Child commit {c.hash[:8]} is dated {diff_child_parent}s "
                                    f"earlier than parent commit {p_hash[:8]}."
                                ),
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                evidence=evidence,
                            )
                        )
                        if len(findings) >= max_findings:
                            return DetectorResult(
                                rule_id=self.get_rule_id(),
                                findings=findings,
                                truncated=True,
                                truncation_reason=("GF006 findings reached the configured limit."),
                            )

            # 3. Future dated commit relative to analysis clock
            future_diff = int((c.committer_date - now).total_seconds())
            if future_diff > self.future_tolerance:
                evidence = Evidence(
                    data={
                        "anomaly_type": "future_commit",
                        "commit_hash": c.hash,
                        "committer_timestamp": c.committer_date.isoformat(),
                        "analysis_clock": now.isoformat(),
                        "calculated_difference_seconds": future_diff,
                        "allowed_tolerance_seconds": self.future_tolerance,
                    }
                )
                findings.append(
                    Finding(
                        rule_id=self.get_rule_id(),
                        title="Future Dated Commit",
                        description=(
                            f"Commit {c.hash[:8]} is timestamped in the future "
                            f"({c.committer_date.isoformat()})."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        evidence=evidence,
                    )
                )
                if len(findings) >= max_findings:
                    return DetectorResult(
                        rule_id=self.get_rule_id(),
                        findings=findings,
                        truncated=True,
                        truncation_reason="GF006 findings reached the configured limit.",
                    )

        return DetectorResult(rule_id=self.get_rule_id(), findings=findings)
