"""GF010: Repository age compared with development history detector."""

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

PREDATING_COMMITS_THRESHOLD_PERCENT: float = 90.0
MIN_COMMITS: int = 5


class RepositoryAgeDetector(BaseDetector):
    """Compares GitHub repository creation timestamp with reachable local Git history."""

    def __init__(
        self,
        predating_threshold_percent: float = PREDATING_COMMITS_THRESHOLD_PERCENT,
        min_commits: int = MIN_COMMITS,
    ) -> None:
        self.predating_threshold_percent = predating_threshold_percent
        self.min_commits = min_commits

    def get_rule_id(self) -> str:
        return "GF010"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        meta = context.github_metadata
        if not meta or context.offline:
            return DetectorResult(
                rule_id=self.get_rule_id(),
                skipped=True,
                skip_reason="GitHub metadata unavailable or offline mode enabled.",
            )

        commits = context.history.commits
        if len(commits) < self.min_commits:
            return DetectorResult(
                rule_id=self.get_rule_id(),
                skipped=True,
                skip_reason=f"Repository has fewer than {self.min_commits} commits.",
            )

        summary = get_analysis_summary(context)
        earliest_dt = summary.earliest_committer_date
        latest_dt = summary.latest_committer_date
        assert earliest_dt is not None and latest_dt is not None
        created_at = meta.created_at

        predating = [c for c in commits if c.committer_date < created_at]
        predating_count = len(predating)
        predating_percentage = round((predating_count / len(commits)) * 100.0, 2)

        diff_sec = int((created_at - earliest_dt).total_seconds())

        if predating_count > 0:
            if meta.is_fork:
                severity = Severity.INFO
                title = "Fork Commit History Predates Repository Creation"
                desc = (
                    f"Repository is a fork of {meta.parent_owner}/{meta.parent_name}; "
                    f"{predating_count} commits ({predating_percentage}%) predate fork creation."
                )
            elif predating_percentage >= self.predating_threshold_percent:
                severity = Severity.MEDIUM
                title = "Imported History Predates GitHub Repository Creation"
                desc = (
                    f"{predating_percentage}% of commits predate GitHub repository creation "
                    f"({created_at.isoformat()})."
                )
            else:
                severity = Severity.INFO
                title = "Commits Predate GitHub Repository Creation"
                desc = (
                    f"Found {predating_count} commits ({predating_percentage}%) predating "
                    f"GitHub repository creation."
                )

            evidence = Evidence(
                data={
                    "github_created_at": created_at.isoformat(),
                    "earliest_commit_timestamp": earliest_dt.isoformat(),
                    "latest_commit_timestamp": latest_dt.isoformat(),
                    "creation_diff_seconds": diff_sec,
                    "commits_predating_creation_count": predating_count,
                    "commits_predating_creation_percentage": predating_percentage,
                    "is_fork": meta.is_fork,
                    "parent_owner": meta.parent_owner,
                    "parent_name": meta.parent_name,
                    "threshold_crossed": self.predating_threshold_percent,
                }
            )

            finding = Finding(
                rule_id=self.get_rule_id(),
                title=title,
                description=desc,
                severity=severity,
                confidence=Confidence.HIGH,
                evidence=evidence,
            )
            return DetectorResult(rule_id=self.get_rule_id(), findings=[finding])

        return DetectorResult(rule_id=self.get_rule_id(), findings=[])
