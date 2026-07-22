"""GF003: Unusual commit bursts detector."""

from gitforensics.analysis_summary import get_analysis_summary
from gitforensics.detectors.base import BaseDetector
from gitforensics.models import (
    CommitNode,
    Confidence,
    DetectorResult,
    Evidence,
    Finding,
    RepositoryContext,
    Severity,
)

WINDOW_DURATION_SECONDS: int = 300
MIN_BURST_COMMITS: int = 10
RATE_THRESHOLD_PER_MINUTE: float = 2.0


class CommitBurstsDetector(BaseDetector):
    """Detects unusually dense commit activity in a short time window."""

    def __init__(
        self,
        window_seconds: int = WINDOW_DURATION_SECONDS,
        min_commits: int = MIN_BURST_COMMITS,
        rate_threshold: float = RATE_THRESHOLD_PER_MINUTE,
    ) -> None:
        self.window_seconds = window_seconds
        self.min_commits = min_commits
        self.rate_threshold = rate_threshold

    def get_rule_id(self) -> str:
        return "GF003"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        commits = get_analysis_summary(context).commits_by_author_date
        if len(commits) < self.min_commits:
            return DetectorResult(
                rule_id=self.get_rule_id(),
                skipped=True,
                skip_reason=f"Repository has fewer than {self.min_commits} commits.",
            )

        max_burst_count = 0
        max_burst_bounds = (0, 0)

        # Sliding window
        left = 0
        for right in range(len(commits)):
            while (
                commits[right].author_date - commits[left].author_date
            ).total_seconds() > self.window_seconds:
                left += 1

            count = right - left + 1
            if count > max_burst_count:
                max_burst_count = count
                max_burst_bounds = (left, right + 1)

        if max_burst_count >= self.min_commits:
            window_minutes = self.window_seconds / 60.0
            cpm = round(max_burst_count / window_minutes, 2)

            if cpm >= self.rate_threshold:
                max_burst_commits: tuple[CommitNode, ...] = commits[
                    max_burst_bounds[0] : max_burst_bounds[1]
                ]
                start_time = max_burst_commits[0].author_date.isoformat()
                end_time = max_burst_commits[-1].author_date.isoformat()
                rep_hashes = [c.hash for c in max_burst_commits[:5]]

                severity = Severity.HIGH if cpm >= 5.0 else Severity.MEDIUM

                evidence = Evidence(
                    data={
                        "window_duration_seconds": self.window_seconds,
                        "commit_count_in_window": max_burst_count,
                        "commits_per_minute": cpm,
                        "start_timestamp": start_time,
                        "end_timestamp": end_time,
                        "representative_commit_hashes": rep_hashes,
                        "threshold_crossed": self.min_commits,
                    }
                )
                finding = Finding(
                    rule_id=self.get_rule_id(),
                    title="Unusual Commit Burst",
                    description=(
                        f"Detected burst of {max_burst_count} commits within "
                        f"{self.window_seconds}s ({cpm} commits/min)."
                    ),
                    severity=severity,
                    confidence=Confidence.HIGH,
                    evidence=evidence,
                )
                return DetectorResult(rule_id=self.get_rule_id(), findings=[finding])

        return DetectorResult(rule_id=self.get_rule_id(), findings=[])
