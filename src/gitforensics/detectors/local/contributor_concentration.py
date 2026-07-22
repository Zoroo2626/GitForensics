"""GF004: Contributor concentration detector."""

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

MIN_REPOSITORY_COMMITS: int = 5
CONCENTRATION_THRESHOLD_PERCENT: float = 90.0


class ContributorConcentrationDetector(BaseDetector):
    """Measures repository activity concentration by normalized contributor identity."""

    def __init__(
        self,
        min_commits: int = MIN_REPOSITORY_COMMITS,
        threshold_percent: float = CONCENTRATION_THRESHOLD_PERCENT,
    ) -> None:
        self.min_commits = min_commits
        self.threshold_percent = threshold_percent

    def get_rule_id(self) -> str:
        return "GF004"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        commits = context.history.commits
        if len(commits) < self.min_commits:
            return DetectorResult(
                rule_id=self.get_rule_id(),
                skipped=True,
                skip_reason=f"Repository has fewer than {self.min_commits} commits.",
            )

        summary = get_analysis_summary(context)
        counts = summary.author_counts
        total_commits = len(commits)
        total_contributors = len(counts)

        top_identity, top_count = counts[0]
        top_percentage = round((top_count / total_commits) * 100.0, 2)

        top_contributors_list = [
            {
                "identity": ident,
                "commit_count": cnt,
                "percentage": round((cnt / total_commits) * 100.0, 2),
            }
            for ident, cnt in counts[:5]
        ]

        if total_contributors == 1:
            evidence = Evidence(
                data={
                    "total_analyzed_commits": total_commits,
                    "total_contributor_identities": 1,
                    "highest_contributor_identity": top_identity,
                    "highest_contributor_commit_count": top_count,
                    "highest_contributor_percentage": 100.0,
                    "top_contributors": top_contributors_list,
                    "threshold_crossed": self.threshold_percent,
                }
            )
            finding = Finding(
                rule_id=self.get_rule_id(),
                title="Single Contributor Repository",
                description=(
                    f"All {total_commits} commits were authored by "
                    f"a single identity ({top_identity})."
                ),
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                evidence=evidence,
            )
            return DetectorResult(rule_id=self.get_rule_id(), findings=[finding])

        if top_percentage >= self.threshold_percent:
            severity = Severity.MEDIUM if total_commits >= 20 else Severity.LOW
            evidence = Evidence(
                data={
                    "total_analyzed_commits": total_commits,
                    "total_contributor_identities": total_contributors,
                    "highest_contributor_identity": top_identity,
                    "highest_contributor_commit_count": top_count,
                    "highest_contributor_percentage": top_percentage,
                    "top_contributors": top_contributors_list,
                    "threshold_crossed": self.threshold_percent,
                }
            )
            finding = Finding(
                rule_id=self.get_rule_id(),
                title="High Contributor Concentration",
                description=(
                    f"Dominant contributor {top_identity} authored {top_percentage}% "
                    f"({top_count}/{total_commits}) of all commits."
                ),
                severity=severity,
                confidence=Confidence.HIGH,
                evidence=evidence,
            )
            return DetectorResult(rule_id=self.get_rule_id(), findings=[finding])

        return DetectorResult(rule_id=self.get_rule_id(), findings=[])
