"""GF001: Initial import concentration detector."""

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

MIN_REPOSITORY_COMMITS: int = 3
CONCENTRATION_THRESHOLD_PERCENT: float = 80.0
HIGH_CONCENTRATION_THRESHOLD_PERCENT: float = 95.0


class InitialImportDetector(BaseDetector):
    """Detects high concentration of file additions/changes in the initial (root) commit."""

    def __init__(
        self,
        min_commits: int = MIN_REPOSITORY_COMMITS,
        threshold_percent: float = CONCENTRATION_THRESHOLD_PERCENT,
    ) -> None:
        self.min_commits = min_commits
        self.threshold_percent = threshold_percent

    def get_rule_id(self) -> str:
        return "GF001"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        commits = context.history.commits
        if len(commits) < self.min_commits:
            return DetectorResult(
                rule_id=self.get_rule_id(),
                skipped=True,
                skip_reason=f"Repository has fewer than {self.min_commits} commits.",
            )

        summary = get_analysis_summary(context)
        root_commits = summary.root_commits
        if not root_commits:
            return DetectorResult(rule_id=self.get_rule_id(), findings=[])

        total_files = summary.total_changed_files
        total_insertions = summary.total_insertions

        findings: list[Finding] = []

        for root in root_commits:
            if total_files > 0:
                percentage = round((root.changed_files_count / total_files) * 100.0, 2)
            elif total_insertions > 0:
                percentage = round((root.insertions / total_insertions) * 100.0, 2)
            else:
                percentage = 0.0

            if percentage >= self.threshold_percent:
                severity = (
                    Severity.HIGH
                    if percentage >= HIGH_CONCENTRATION_THRESHOLD_PERCENT
                    else Severity.MEDIUM
                )
                evidence = Evidence(
                    data={
                        "root_commit_hash": root.hash,
                        "root_file_count": root.changed_files_count,
                        "root_insertions": root.insertions,
                        "total_repository_files": total_files,
                        "total_repository_insertions": total_insertions,
                        "calculated_percentage": percentage,
                        "threshold_crossed": self.threshold_percent,
                    }
                )
                finding = Finding(
                    rule_id=self.get_rule_id(),
                    title="Initial Import Concentration",
                    description=(
                        f"Root commit {root.hash[:8]} contains {percentage}% of all "
                        f"changed files ({root.changed_files_count}/{total_files})."
                    ),
                    severity=severity,
                    confidence=Confidence.HIGH,
                    evidence=evidence,
                )
                findings.append(finding)
                if len(findings) >= context.security_limits.max_findings:
                    return DetectorResult(
                        rule_id=self.get_rule_id(),
                        findings=findings,
                        truncated=True,
                        truncation_reason="GF001 findings reached the configured limit.",
                    )

        return DetectorResult(rule_id=self.get_rule_id(), findings=findings)
