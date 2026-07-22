"""GF005: Author and committer identity mismatches detector."""

from collections import Counter

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

MIN_MISMATCH_COMMITS: int = 3
MIN_MISMATCH_PERCENTAGE: float = 20.0


class IdentityMismatchesDetector(BaseDetector):
    """Detects systematic differences between author and committer identities."""

    def __init__(
        self,
        min_mismatches: int = MIN_MISMATCH_COMMITS,
        min_percentage: float = MIN_MISMATCH_PERCENTAGE,
    ) -> None:
        self.min_mismatches = min_mismatches
        self.min_percentage = min_percentage

    def get_rule_id(self) -> str:
        return "GF005"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        commits = context.history.commits
        total_commits = len(commits)
        if total_commits == 0:
            return DetectorResult(rule_id=self.get_rule_id(), findings=[])

        mismatch_count = 0
        representative_hashes: list[str] = []
        pair_counts: Counter[tuple[str, str]] = Counter()
        distinct_authors: set[str] = set()
        distinct_committers: set[str] = set()

        summary = get_analysis_summary(context)
        for c, author, committer in zip(
            commits,
            summary.normalized_author_identities,
            summary.normalized_committer_identities,
            strict=True,
        ):
            if author and committer and author != committer:
                mismatch_count += 1
                pair_counts[(author, committer)] += 1
                distinct_authors.add(author)
                distinct_committers.add(committer)
                if len(representative_hashes) < 5:
                    representative_hashes.append(c.hash)

        percentage = round((mismatch_count / total_commits) * 100.0, 2)

        if mismatch_count >= self.min_mismatches and percentage >= self.min_percentage:
            distinct_author_count = len(distinct_authors)
            distinct_committer_count = len(distinct_committers)

            top_pairs = [
                {"author": p[0], "committer": p[1], "count": cnt}
                for p, cnt in pair_counts.most_common(5)
            ]

            severity = (
                Severity.MEDIUM
                if (
                    percentage >= 50.0
                    and distinct_author_count >= 3
                    and distinct_committer_count == 1
                )
                else Severity.LOW
            )

            evidence = Evidence(
                data={
                    "total_mismatched_commits": mismatch_count,
                    "total_commits": total_commits,
                    "mismatch_percentage": percentage,
                    "top_author_committer_pairs": top_pairs,
                    "distinct_committers_count": distinct_committer_count,
                    "distinct_authors_count": distinct_author_count,
                    "threshold_crossed": self.min_percentage,
                    "representative_commit_hashes": representative_hashes,
                }
            )
            finding = Finding(
                rule_id=self.get_rule_id(),
                title="Author/Committer Identity Mismatches",
                description=(
                    f"Found {mismatch_count} commits ({percentage}%) with mismatched "
                    f"author and committer identities."
                ),
                severity=severity,
                confidence=Confidence.MEDIUM,
                evidence=evidence,
            )
            return DetectorResult(rule_id=self.get_rule_id(), findings=[finding])

        return DetectorResult(rule_id=self.get_rule_id(), findings=[])
