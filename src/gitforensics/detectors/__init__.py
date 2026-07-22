"""Detector registry and factory for GitForensics."""

from gitforensics.detectors.base import BaseDetector
from gitforensics.detectors.local.commit_bursts import CommitBurstsDetector
from gitforensics.detectors.local.contributor_concentration import (
    ContributorConcentrationDetector,
)
from gitforensics.detectors.local.history_modifying_workflows import (
    HistoryModifyingWorkflowsDetector,
)
from gitforensics.detectors.local.identity_mismatches import IdentityMismatchesDetector
from gitforensics.detectors.local.initial_import import InitialImportDetector
from gitforensics.detectors.local.regular_intervals import RegularIntervalsDetector
from gitforensics.detectors.local.signature_coverage import SignatureCoverageDetector
from gitforensics.detectors.local.tag_anomalies import TagAnomaliesDetector
from gitforensics.detectors.local.timestamp_ordering import TimestampOrderingDetector
from gitforensics.detectors.remote.release_provenance import (
    AssetDigestAndAttestationDetector,
    AssetHeavyMinimalSourceDetector,
    MutableReleaseAssetDetector,
    ReleaseChronologyConflictDetector,
    ReleaseUnresolvableDetector,
    RepeatedReleaseTargetsDetector,
)
from gitforensics.detectors.remote.repository_age import RepositoryAgeDetector


def get_default_detectors() -> list[BaseDetector]:
    """Instantiates and returns the default list of registered detectors."""
    return [
        InitialImportDetector(),
        RegularIntervalsDetector(),
        CommitBurstsDetector(),
        ContributorConcentrationDetector(),
        IdentityMismatchesDetector(),
        TimestampOrderingDetector(),
        SignatureCoverageDetector(),
        HistoryModifyingWorkflowsDetector(),
        TagAnomaliesDetector(),
        RepositoryAgeDetector(),
        ReleaseUnresolvableDetector(),
        RepeatedReleaseTargetsDetector(),
        ReleaseChronologyConflictDetector(),
        AssetHeavyMinimalSourceDetector(),
        MutableReleaseAssetDetector(),
        AssetDigestAndAttestationDetector(),
    ]


__all__ = [
    "AssetDigestAndAttestationDetector",
    "AssetHeavyMinimalSourceDetector",
    "BaseDetector",
    "CommitBurstsDetector",
    "ContributorConcentrationDetector",
    "HistoryModifyingWorkflowsDetector",
    "IdentityMismatchesDetector",
    "InitialImportDetector",
    "MutableReleaseAssetDetector",
    "RegularIntervalsDetector",
    "ReleaseChronologyConflictDetector",
    "ReleaseUnresolvableDetector",
    "RepeatedReleaseTargetsDetector",
    "RepositoryAgeDetector",
    "SignatureCoverageDetector",
    "TagAnomaliesDetector",
    "TimestampOrderingDetector",
    "get_default_detectors",
]
