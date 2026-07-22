"""GF007: Commit signature coverage detector."""

from gitforensics.detectors.base import BaseDetector
from gitforensics.models import (
    Confidence,
    DetectorResult,
    Evidence,
    Finding,
    RepositoryContext,
    Severity,
    SignatureStatus,
)

MIN_COMMITS: int = 5


class SignatureCoverageDetector(BaseDetector):
    """Evaluates Git GPG/SSH signature coverage and reports verification failures."""

    def __init__(self, min_commits: int = MIN_COMMITS) -> None:
        self.min_commits = min_commits

    def get_rule_id(self) -> str:
        return "GF007"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        commits = context.history.commits
        total_commits = len(commits)
        if total_commits == 0:
            return DetectorResult(rule_id=self.get_rule_id(), findings=[])

        signed_count = 0
        valid_count = 0
        invalid_count = 0
        unsigned_count = 0
        bad_or_revoked = False
        failed_sig_commits_data: list[dict[str, str]] = []
        representative_invalid_hashes: list[str] = []

        for c in commits:
            status = c.signature_status
            if status == SignatureStatus.VALID:
                signed_count += 1
                valid_count += 1
            elif status in (
                SignatureStatus.BAD,
                SignatureStatus.REVOKED_KEY,
                SignatureStatus.EXPIRED_KEY,
                SignatureStatus.EXPIRED_SIGNATURE,
                SignatureStatus.VERIFICATION_ERROR,
                SignatureStatus.UNKNOWN_TRUST,
            ):
                signed_count += 1
                invalid_count += 1
                bad_or_revoked = bad_or_revoked or status in (
                    SignatureStatus.BAD,
                    SignatureStatus.REVOKED_KEY,
                )
                if len(failed_sig_commits_data) < context.security_limits.max_evidence_items:
                    failed_sig_commits_data.append({"hash": c.hash, "status": status.value})
                if len(representative_invalid_hashes) < 5:
                    representative_invalid_hashes.append(c.hash)
            else:
                unsigned_count += 1

        coverage_percentage = round((signed_count / total_commits) * 100.0, 2)

        findings: list[Finding] = []

        # 1. Verification failures finding (if any invalid/failed signatures present)
        if invalid_count:
            severity = Severity.HIGH if bad_or_revoked else Severity.MEDIUM

            evidence = Evidence(
                data={
                    "total_commits": total_commits,
                    "signed_commit_count": signed_count,
                    "valid_signature_count": valid_count,
                    "invalid_signature_count": invalid_count,
                    "unsigned_commit_count": unsigned_count,
                    "signature_coverage_percentage": coverage_percentage,
                    "failed_signature_commits": failed_sig_commits_data,
                    "representative_commit_hashes": representative_invalid_hashes,
                }
            )
            finding = Finding(
                rule_id=self.get_rule_id(),
                title="Commit Signature Verification Failure",
                description=(
                    f"Found {invalid_count} commit(s) with invalid or failed "
                    f"signature verification states."
                ),
                severity=severity,
                confidence=Confidence.HIGH,
                evidence=evidence,
            )
            findings.append(finding)

        # 2. Informational signature coverage summary (if total commits >= min_commits)
        if total_commits >= self.min_commits and not invalid_count:
            evidence = Evidence(
                data={
                    "total_commits": total_commits,
                    "signed_commit_count": signed_count,
                    "valid_signature_count": valid_count,
                    "invalid_signature_count": 0,
                    "unsigned_commit_count": unsigned_count,
                    "signature_coverage_percentage": coverage_percentage,
                    "failed_signature_commits": [],
                    "representative_commit_hashes": [c.hash for c in commits[:5]],
                }
            )
            finding = Finding(
                rule_id=self.get_rule_id(),
                title="Commit Signature Coverage Summary",
                description=(
                    f"Signature coverage is {coverage_percentage}% "
                    f"({signed_count}/{total_commits} signed)."
                ),
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                evidence=evidence,
            )
            findings.append(finding)

        return DetectorResult(rule_id=self.get_rule_id(), findings=findings)
