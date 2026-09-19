"""Release provenance detectors for GitForensics (GF011-GF016)."""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import TYPE_CHECKING

from gitforensics.analysis_summary import get_analysis_summary
from gitforensics.compat import UTC
from gitforensics.detectors.base import BaseDetector
from gitforensics.models import Confidence, DetectorResult, Evidence, Finding, Severity
from gitforensics.release_analysis import collect_commit_ancestors
from gitforensics.release_models import (
    AssetCategory,
    AttestationState,
    DigestState,
    ResolvedRelease,
)

if TYPE_CHECKING:
    from gitforensics.models import RepositoryContext

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Thresholds
# --------------------------------------------------------------------------
# GF012: Min releases to the same commit before flagging
_SAME_COMMIT_MIN_RELEASES = 3

# GF014: Min binary asset bytes total per source commit to trigger
_MIN_BINARY_BYTES_PER_COMMIT = 500_000  # 500 KiB per commit

# GF014: Min binary asset count to flag
_MIN_BINARY_ASSET_COUNT = 1

# GF014: Max source commits to still consider "minimal"
_MAX_MINIMAL_COMMITS = 2

# GF015: Asset update threshold seconds after publication
_ASSET_LATE_UPDATE_SECONDS = 60 * 60  # 1 hour

# GF013: Semver-like pattern
_SEMVER_PATTERN = re.compile(r"v?(\d+)\.(\d+)(?:\.(\d+))?(?:[.-]([a-zA-Z0-9.]+))?$")


def _try_parse_version(name: str) -> tuple[int, int, int] | None:
    """Attempts to parse a simple version triple from a release name.

    Returns (major, minor, patch) or None if name is not semver-like.
    Ignores pre-release suffixes when comparing ordering.
    """
    # Match against the tag name or release name
    for candidate in (name, name.lstrip("v")):
        m = _SEMVER_PATTERN.match(candidate)
        if m:
            major = int(m.group(1))
            minor = int(m.group(2))
            patch = int(m.group(3) or 0)
            return (major, minor, patch)
    return None


def _bounded_detector_result(
    context: RepositoryContext, rule_id: str, findings: list[Finding]
) -> DetectorResult:
    """Return a typed truncation state when a detector reaches its run-local cap."""
    truncated = len(findings) >= context.security_limits.max_findings
    return DetectorResult(
        rule_id=rule_id,
        findings=findings,
        truncated=truncated,
        truncation_reason=(
            f"{rule_id} findings reached the configured limit." if truncated else ""
        ),
    )


class ReleaseUnresolvableDetector(BaseDetector):
    """GF011: Release without a resolvable source revision.

    Reports releases whose tag or target commitish cannot be connected
    to a reachable analyzed commit.
    """

    def get_rule_id(self) -> str:
        return "GF011"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        """Analyze resolved releases for unresolvable source revisions."""
        release_result = getattr(context, "release_analysis_result", None)
        if release_result is None or not release_result.releases:
            return DetectorResult(
                rule_id=self.get_rule_id(),
                skipped=True,
                skip_reason="No release analysis results available.",
            )

        findings: list[Finding] = []
        history_is_incomplete = context.history.is_limited

        for rr in release_result.releases:
            if len(findings) >= context.security_limits.max_findings:
                break
            if not rr.resolution_failed:
                continue

            # Conservative severity when history is shallow/incomplete
            severity = Severity.LOW if history_is_incomplete else Severity.MEDIUM
            confidence = Confidence.LOW if history_is_incomplete else Confidence.MEDIUM

            findings.append(
                Finding(
                    rule_id=self.get_rule_id(),
                    title="Release without resolvable source revision",
                    description=(
                        f"Release '{rr.release.name}' (tag: {rr.release.tag_name!r}) "
                        "could not be connected to a commit in the analyzed history. "
                        + (
                            "Note: history appears incomplete, reducing confidence. "
                            if history_is_incomplete
                            else ""
                        )
                        + f"Reason: {rr.resolution_failure_reason}"
                    ),
                    severity=severity,
                    confidence=confidence,
                    evidence=Evidence(
                        data={
                            "release_id": rr.release.release_id,
                            "release_name": rr.release.name,
                            "tag_name": rr.release.tag_name,
                            "target_commitish": rr.release.target_commitish,
                            "published_at": (
                                rr.release.published_at.isoformat()
                                if rr.release.published_at
                                else None
                            ),
                            "resolution_attempts": [
                                "local_tag_lookup: "
                                + ("found" if rr.local_tag_found else "not found"),
                                "commitish_prefix_match: "
                                + ("skipped" if rr.local_tag_found else "attempted"),
                            ],
                            "failure_reason": rr.resolution_failure_reason,
                            "history_is_incomplete": history_is_incomplete,
                        }
                    ),
                )
            )

        return _bounded_detector_result(context, self.get_rule_id(), findings)


class RepeatedReleaseTargetsDetector(BaseDetector):
    """GF012: Multiple releases resolving to the same commit.

    Detects many releases or version tags all pointing to the same commit,
    which may indicate cloned/backdated releases.
    """

    def get_rule_id(self) -> str:
        return "GF012"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        release_result = getattr(context, "release_analysis_result", None)
        if release_result is None or not release_result.releases:
            return DetectorResult(
                rule_id=self.get_rule_id(),
                skipped=True,
                skip_reason="No release analysis results available.",
            )

        # Group releases by resolved commit hash
        by_commit: dict[str, list[ResolvedRelease]] = {}
        for rr in release_result.releases:
            if rr.resolved_commit_hash:
                by_commit.setdefault(rr.resolved_commit_hash, []).append(rr)

        findings: list[Finding] = []
        for commit_hash, group in by_commit.items():
            if len(findings) >= context.security_limits.max_findings:
                break
            if len(group) < _SAME_COMMIT_MIN_RELEASES:
                continue

            # Compute publication window
            pub_times = [rr.release.published_at for rr in group if rr.release.published_at]
            if pub_times:
                window_seconds = (max(pub_times) - min(pub_times)).total_seconds()
                window_str = f"{int(window_seconds)}s"
            else:
                window_str = "unknown"

            evidence_limit = context.security_limits.max_evidence_items
            affected = [rr.release.name or rr.release.tag_name for rr in group[:evidence_limit]]
            tag_names = [rr.release.tag_name for rr in group[:evidence_limit]]

            findings.append(
                Finding(
                    rule_id=self.get_rule_id(),
                    title="Multiple releases targeting the same commit",
                    description=(
                        f"{len(group)} releases all resolve to commit "
                        f"'{commit_hash[:12]}...' - this may indicate "
                        "reissued or cloned releases targeting the same codebase state."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    evidence=Evidence(
                        data={
                            "shared_target_commit": commit_hash,
                            "release_count": len(group),
                            "affected_releases": affected,
                            "tag_names": tag_names,
                            "publication_window": window_str,
                            "threshold": _SAME_COMMIT_MIN_RELEASES,
                        }
                    ),
                )
            )

        return _bounded_detector_result(context, self.get_rule_id(), findings)


class ReleaseChronologyConflictDetector(BaseDetector):
    """GF013: Release chronology conflict between version order, publish order, and ancestry.

    Only triggers when version names can be confidently parsed as semver.
    """

    def get_rule_id(self) -> str:
        return "GF013"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        release_result = getattr(context, "release_analysis_result", None)
        if release_result is None or len(release_result.releases) < 2:
            return DetectorResult(
                rule_id=self.get_rule_id(),
                skipped=True,
                skip_reason="Insufficient release data for chronology analysis.",
            )

        findings: list[Finding] = []
        commit_by_hash = get_analysis_summary(context).commit_by_hash

        resolved = sorted(
            release_result.releases,
            key=lambda r: r.release.published_at or datetime(1970, 1, 1, tzinfo=UTC),
        )

        for i in range(1, len(resolved)):
            if len(findings) >= context.security_limits.max_findings:
                break
            curr = resolved[i]
            prev = resolved[i - 1]

            curr_version = _try_parse_version(curr.release.name or curr.release.tag_name)
            prev_version = _try_parse_version(prev.release.name or prev.release.tag_name)

            if curr_version is None or prev_version is None:
                continue  # Cannot parse - skip per spec

            # Version order should be non-decreasing when sorted by publication time
            if curr_version < prev_version:
                # Confirm with commit ancestry if possible
                ancestry_conflict_confirmed = False
                ancestry_desc = "ancestry not determined"
                curr_hash = curr.resolved_commit_hash
                prev_hash = prev.resolved_commit_hash
                if curr_hash in commit_by_hash and prev_hash in commit_by_hash:
                    prev_ancestors, _ = collect_commit_ancestors(prev_hash, commit_by_hash)
                    if curr_hash != prev_hash and curr_hash in prev_ancestors:
                        ancestry_conflict_confirmed = True
                        ancestry_desc = (
                            f"commit of '{curr.release.name}' is older than "
                            f"commit of '{prev.release.name}' in ancestry"
                        )
                    else:
                        curr_ancestors, _ = collect_commit_ancestors(curr_hash, commit_by_hash)
                        if prev_hash in curr_ancestors:
                            ancestry_desc = "commit ancestry consistent with publication order"

                findings.append(
                    Finding(
                        rule_id=self.get_rule_id(),
                        title="Release version order conflicts with publication order",
                        description=(
                            f"Release '{curr.release.name}' (version {curr_version}) "
                            f"was published AFTER '{prev.release.name}' "
                            f"(version {prev_version}) but has a lower version number. "
                            f"Ancestry: {ancestry_desc}."
                        ),
                        severity=(Severity.MEDIUM if ancestry_conflict_confirmed else Severity.LOW),
                        confidence=(
                            Confidence.HIGH if ancestry_conflict_confirmed else Confidence.MEDIUM
                        ),
                        evidence=Evidence(
                            data={
                                "older_release_name": curr.release.name,
                                "older_release_version": list(curr_version),
                                "older_release_published_at": (
                                    curr.release.published_at.isoformat()
                                    if curr.release.published_at
                                    else None
                                ),
                                "older_release_commit": curr.resolved_commit_hash,
                                "newer_release_name": prev.release.name,
                                "newer_release_version": list(prev_version),
                                "newer_release_published_at": (
                                    prev.release.published_at.isoformat()
                                    if prev.release.published_at
                                    else None
                                ),
                                "newer_release_commit": prev.resolved_commit_hash,
                                "ancestry_relationship": ancestry_desc,
                                "ordering_conflict": (
                                    "version regressed after publication time increased"
                                ),
                            }
                        ),
                    )
                )

        return _bounded_detector_result(context, self.get_rule_id(), findings)


class AssetHeavyMinimalSourceDetector(BaseDetector):
    """GF014: Asset-heavy release with minimal source change.

    Contextual evidence only. Does not claim the release is malicious.
    """

    def get_rule_id(self) -> str:
        return "GF014"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        release_result = getattr(context, "release_analysis_result", None)
        if release_result is None or not release_result.releases:
            return DetectorResult(
                rule_id=self.get_rule_id(),
                skipped=True,
                skip_reason="No release analysis results available.",
            )

        findings: list[Finding] = []

        for release_index, rr in enumerate(release_result.releases):
            if len(findings) >= context.security_limits.max_findings:
                break
            binary_assets = [a for a in rr.release.assets if a.is_binary_or_packaged()]
            non_source_binaries = [
                a for a in binary_assets if a.category != AssetCategory.SOURCE_ARCHIVE
            ]

            if not non_source_binaries:
                continue

            total_binary_bytes = sum(a.size for a in non_source_binaries)
            binary_count = len(non_source_binaries)

            commits_since = rr.commits_since_prev
            files_since = rr.files_changed_since_prev

            if commits_since is None and release_index > 0:
                continue  # Missing ancestry cannot establish minimal source change.
            is_first_release = commits_since is None
            if is_first_release:
                # First release: contextual info only, not a strong finding
                if total_binary_bytes < _MIN_BINARY_BYTES_PER_COMMIT:
                    continue
                findings.append(
                    Finding(
                        rule_id=self.get_rule_id(),
                        title="First release contains substantial binary assets",
                        description=(
                            f"Release '{rr.release.name}' is the first release and "
                            f"contains {binary_count} binary/packaged asset(s) "
                            f"totalling {total_binary_bytes:,} bytes. "
                            "No prior release exists for comparison. "
                            "This is contextual information only."
                        ),
                        severity=Severity.INFO,
                        confidence=Confidence.LOW,
                        evidence=Evidence(
                            data={
                                "release_id": rr.release.release_id,
                                "release_name": rr.release.name,
                                "binary_asset_count": binary_count,
                                "total_asset_bytes": total_binary_bytes,
                                "asset_names": [
                                    a.name
                                    for a in non_source_binaries[
                                        : context.security_limits.max_evidence_items
                                    ]
                                ],
                                "asset_categories": [
                                    a.category.value
                                    for a in non_source_binaries[
                                        : context.security_limits.max_evidence_items
                                    ]
                                ],
                                "commits_since_prev": None,
                                "files_changed_since_prev": None,
                                "note": "first release",
                            }
                        ),
                    )
                )
                continue

            # Subsequent release: compare binary size to source changes
            assert commits_since is not None
            bytes_per_commit = (
                total_binary_bytes / commits_since if commits_since > 0 else float("inf")
            )
            minimal_source = (commits_since <= _MAX_MINIMAL_COMMITS) or (
                bytes_per_commit > _MIN_BINARY_BYTES_PER_COMMIT
            )

            if not minimal_source:
                continue

            findings.append(
                Finding(
                    rule_id=self.get_rule_id(),
                    title="Asset-heavy release with minimal source change",
                    description=(
                        f"Release '{rr.release.name}' contains {binary_count} binary/packaged "
                        f"asset(s) totalling {total_binary_bytes:,} bytes, but only "
                        f"{commits_since} commit(s) and {files_since or 0} file change(s) "
                        "occurred since the previous release. "
                        "This is contextual evidence only and does not indicate maliciousness."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    evidence=Evidence(
                        data={
                            "release_id": rr.release.release_id,
                            "release_name": rr.release.name,
                            "binary_asset_count": binary_count,
                            "total_asset_bytes": total_binary_bytes,
                            "asset_names": [
                                a.name
                                for a in non_source_binaries[
                                    : context.security_limits.max_evidence_items
                                ]
                            ],
                            "asset_categories": [
                                a.category.value
                                for a in non_source_binaries[
                                    : context.security_limits.max_evidence_items
                                ]
                            ],
                            "commits_since_prev": commits_since,
                            "files_changed_since_prev": files_since,
                            "insertions_since_prev": rr.insertions_since_prev,
                            "deletions_since_prev": rr.deletions_since_prev,
                            "bytes_per_commit_ratio": round(bytes_per_commit, 2)
                            if bytes_per_commit != float("inf")
                            else "infinite",
                            "threshold_commits": _MAX_MINIMAL_COMMITS,
                            "threshold_bytes_per_commit": _MIN_BINARY_BYTES_PER_COMMIT,
                        }
                    ),
                )
            )

        return _bounded_detector_result(context, self.get_rule_id(), findings)


class MutableReleaseAssetDetector(BaseDetector):
    """GF015: Mutable or late-updated release asset.

    Uses asset timestamp metadata only. Does not claim replacement definitively.
    """

    def get_rule_id(self) -> str:
        return "GF015"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        release_result = getattr(context, "release_analysis_result", None)
        if release_result is None or not release_result.releases:
            return DetectorResult(
                rule_id=self.get_rule_id(),
                skipped=True,
                skip_reason="No release analysis results available.",
            )

        findings: list[Finding] = []

        for rr in release_result.releases:
            if len(findings) >= context.security_limits.max_findings:
                break
            pub_at = rr.release.published_at
            if not pub_at:
                continue

            for asset in rr.release.assets:
                if len(findings) >= context.security_limits.max_findings:
                    break
                updated_at = asset.updated_at
                created_at = asset.created_at

                # Check asset creation after publication
                created_after_pub = (
                    created_at > pub_at
                    and (created_at - pub_at).total_seconds() > _ASSET_LATE_UPDATE_SECONDS
                )

                # Check substantial update time after asset creation
                update_lag = (updated_at - created_at).total_seconds()
                substantially_updated = update_lag > _ASSET_LATE_UPDATE_SECONDS

                if not (created_after_pub or substantially_updated):
                    continue

                if created_after_pub:
                    reason = (
                        f"Asset was created {int((created_at - pub_at).total_seconds())}s "
                        "after release publication."
                    )
                    severity = Severity.LOW
                else:
                    reason = (
                        f"Asset metadata was updated {int(update_lag)}s "
                        "after initial asset creation."
                    )
                    severity = Severity.INFO

                findings.append(
                    Finding(
                        rule_id=self.get_rule_id(),
                        title="Release asset updated substantially after publication",
                        description=(
                            f"Asset '{asset.name}' in release '{rr.release.name}' shows "
                            "a substantial time gap between release publication and asset "
                            "creation/update timestamps. "
                            f"{reason} "
                            "This is an observable metadata anomaly and does not confirm "
                            "that the asset was replaced."
                        ),
                        severity=severity,
                        confidence=Confidence.MEDIUM,
                        evidence=Evidence(
                            data={
                                "release_id": rr.release.release_id,
                                "release_name": rr.release.name,
                                "asset_id": asset.asset_id,
                                "asset_name": asset.name,
                                "release_published_at": pub_at.isoformat(),
                                "asset_created_at": created_at.isoformat(),
                                "asset_updated_at": updated_at.isoformat(),
                                "created_after_pub_seconds": int(
                                    (created_at - pub_at).total_seconds()
                                )
                                if created_after_pub
                                else 0,
                                "update_lag_seconds": int(update_lag),
                                "threshold_seconds": _ASSET_LATE_UPDATE_SECONDS,
                                "observation": reason,
                            }
                        ),
                    )
                )

        return _bounded_detector_result(context, self.get_rule_id(), findings)


class AssetDigestAndAttestationDetector(BaseDetector):
    """GF016: Missing or problematic asset digest and attestation mismatch.

    Classifies digest availability and reports confirmed attestation mismatches.
    Missing digests are informational. Mismatches may be HIGH severity.
    """

    def get_rule_id(self) -> str:
        return "GF016"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        release_result = getattr(context, "release_analysis_result", None)
        if release_result is None or not release_result.releases:
            return DetectorResult(
                rule_id=self.get_rule_id(),
                skipped=True,
                skip_reason="No release analysis results available.",
            )

        findings: list[Finding] = []

        for rr in release_result.releases:
            if len(findings) >= context.security_limits.max_findings:
                break
            for asset in rr.release.assets:
                if len(findings) >= context.security_limits.max_findings:
                    break
                # Skip source archives from digest reporting
                if asset.category == AssetCategory.SOURCE_ARCHIVE:
                    continue

                digest_state = asset.digest_state

                # Confirmed digest mismatch: HIGH severity
                if digest_state == DigestState.DOWNLOADED_DIGEST_MISMATCH:
                    findings.append(
                        Finding(
                            rule_id=self.get_rule_id(),
                            title="Release asset digest mismatch",
                            description=(
                                f"Asset '{asset.name}' in release '{rr.release.name}' "
                                "has a calculated SHA-256 digest that does not match "
                                "the server-provided digest. This strongly suggests "
                                "the asset content differs from what the server recorded."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            evidence=Evidence(
                                data={
                                    "release_id": rr.release.release_id,
                                    "release_name": rr.release.name,
                                    "asset_id": asset.asset_id,
                                    "asset_name": asset.name,
                                    "asset_size": asset.size,
                                    "expected_digest": asset.server_digest,
                                    "calculated_digest": asset.calculated_digest,
                                    "verification_state": digest_state.value,
                                    "bytes_processed": asset.bytes_processed,
                                }
                            ),
                        )
                    )

                # Missing digest: informational only
                elif digest_state == DigestState.DIGEST_MISSING and asset.is_binary_or_packaged():
                    findings.append(
                        Finding(
                            rule_id=self.get_rule_id(),
                            title="Release asset has no server-provided digest",
                            description=(
                                f"Asset '{asset.name}' in release '{rr.release.name}' "
                                "has no SHA-256 digest provided by the GitHub API. "
                                "A missing digest is informational and not evidence of tampering."
                            ),
                            severity=Severity.INFO,
                            confidence=Confidence.HIGH,
                            evidence=Evidence(
                                data={
                                    "release_id": rr.release.release_id,
                                    "release_name": rr.release.name,
                                    "asset_id": asset.asset_id,
                                    "asset_name": asset.name,
                                    "asset_size": asset.size,
                                    "expected_digest": None,
                                    "calculated_digest": None,
                                    "verification_state": digest_state.value,
                                    "bytes_processed": 0,
                                }
                            ),
                        )
                    )

            # Attestation mismatch findings
            if rr.attestation_state == AttestationState.REPOSITORY_IDENTITY_MISMATCH:
                findings.append(
                    Finding(
                        rule_id=self.get_rule_id(),
                        title="Release attestation repository identity mismatch",
                        description=(
                            f"Release '{rr.release.name}' has an attestation record "
                            "but the attested repository identity does not match the "
                            "expected repository. This may indicate the artifact was "
                            "built from a different repository."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        evidence=Evidence(
                            data={
                                "release_id": rr.release.release_id,
                                "release_name": rr.release.name,
                                "subject_digest": rr.attestation_subject_digest,
                                "attested_repository": rr.attestation_repository,
                                "attestation_state": rr.attestation_state.value,
                                "workflow_reference": rr.attestation_workflow,
                                "cryptographic_verification_performed": False,
                                "note": "Metadata-based analysis only. "
                                "No cryptographic verification was performed.",
                            }
                        ),
                    )
                )

        return _bounded_detector_result(context, self.get_rule_id(), findings)
