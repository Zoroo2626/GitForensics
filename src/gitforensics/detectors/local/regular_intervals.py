"""GF002: Mechanically regular commit intervals detector."""

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

MIN_SAMPLE_SIZE_INTERVALS: int = 5
INTERVAL_TOLERANCE_SECONDS: int = 2
MATCH_PERCENTAGE_THRESHOLD: float = 50.0
HIGH_MATCH_PERCENTAGE_THRESHOLD: float = 80.0


class RegularIntervalsDetector(BaseDetector):
    """Detects repeated commit intervals that are mechanically uniform."""

    def __init__(
        self,
        min_intervals: int = MIN_SAMPLE_SIZE_INTERVALS,
        tolerance: int = INTERVAL_TOLERANCE_SECONDS,
        match_threshold: float = MATCH_PERCENTAGE_THRESHOLD,
    ) -> None:
        self.min_intervals = min_intervals
        self.tolerance = tolerance
        self.match_threshold = match_threshold

    def get_rule_id(self) -> str:
        return "GF002"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        non_merges = get_analysis_summary(context).non_merge_commits_by_author_date

        if len(non_merges) <= self.min_intervals:
            return DetectorResult(
                rule_id=self.get_rule_id(),
                skipped=True,
                skip_reason=f"Insufficient non-merge commits (need > {self.min_intervals}).",
            )

        interval_commits: list[tuple[int, str]] = []

        for i in range(1, len(non_merges)):
            prev_c = non_merges[i - 1]
            curr_c = non_merges[i]
            diff_sec = int((curr_c.author_date - prev_c.author_date).total_seconds())
            if diff_sec > 0:  # Ignore 0s batch commits
                interval_commits.append((diff_sec, curr_c.hash))

        if len(interval_commits) < self.min_intervals:
            return DetectorResult(
                rule_id=self.get_rule_id(),
                skipped=True,
                skip_reason="Insufficient positive time intervals.",
            )

        # Fixed-width buckets keep hostile all-unique intervals O(n), not O(n^2).
        bucket_width = max(1, (self.tolerance * 2) + 1)
        counts: Counter[int] = Counter(
            round(interval / bucket_width) * bucket_width for interval, _hash in interval_commits
        )

        dominant_interval, matched_count = counts.most_common(1)[0]
        matching_percentage = round((matched_count / len(interval_commits)) * 100.0, 2)

        if matching_percentage >= self.match_threshold:
            severity = (
                Severity.HIGH
                if matching_percentage >= HIGH_MATCH_PERCENTAGE_THRESHOLD
                else Severity.MEDIUM
            )
            rep_hashes = [
                h
                for diff, h in interval_commits
                if round(diff / bucket_width) * bucket_width == dominant_interval
            ][:5]

            evidence = Evidence(
                data={
                    "dominant_interval_seconds": dominant_interval,
                    "matched_intervals_count": matched_count,
                    "total_intervals_analyzed": len(interval_commits),
                    "matching_percentage": matching_percentage,
                    "tolerance_seconds": self.tolerance,
                    "threshold_crossed": self.match_threshold,
                    "representative_commit_hashes": rep_hashes,
                }
            )
            finding = Finding(
                rule_id=self.get_rule_id(),
                title="Mechanically Regular Commit Intervals",
                description=(
                    f"{matching_percentage}% of analyzed intervals match a dominant "
                    f"cadence of ~{dominant_interval}s (±{self.tolerance}s)."
                ),
                severity=severity,
                confidence=Confidence.HIGH,
                evidence=evidence,
            )
            return DetectorResult(rule_id=self.get_rule_id(), findings=[finding])

        return DetectorResult(rule_id=self.get_rule_id(), findings=[])
