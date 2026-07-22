"""Typed data models for GitHub release metadata, asset provenance, and attestation."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from gitforensics.compat import StrEnum


class AssetCategory(StrEnum):
    """Broad classification of release asset content type."""

    WINDOWS_EXE = "windows_exe"
    SHARED_LIBRARY = "shared_library"
    DISK_IMAGE = "disk_image"
    INSTALLER = "installer"
    JAVA_ARCHIVE = "java_archive"
    PYTHON_WHEEL = "python_wheel"
    PYTHON_SDIST = "python_sdist"
    NODE_PACKAGE = "node_package"
    COMPRESSED_ARCHIVE = "compressed_archive"
    CHECKSUM = "checksum"
    SIGNATURE = "signature"
    SBOM = "sbom"
    SOURCE_ARCHIVE = "source_archive"
    UNKNOWN = "unknown"


class DigestState(StrEnum):
    """Classification of asset digest availability and verification outcome."""

    SERVER_SHA256_AVAILABLE = "server_sha256_available"
    DIGEST_MISSING = "digest_missing"
    DIGEST_MALFORMED = "digest_malformed"
    DOWNLOADED_DIGEST_MATCHED = "downloaded_digest_matched"
    DOWNLOADED_DIGEST_MISMATCH = "downloaded_digest_mismatch"
    DOWNLOAD_FAILED = "download_failed"
    VERIFICATION_SKIPPED = "verification_skipped"


class AttestationState(StrEnum):
    """Possible outcomes of artifact attestation lookup and matching."""

    MATCHING_ATTESTATION_FOUND = "matching_attestation_found"
    ATTESTATION_FOUND_DIFFERENT_DIGEST = "attestation_found_different_digest"
    NO_ATTESTATION_FOUND = "no_attestation_found"
    ATTESTATION_LOOKUP_UNAVAILABLE = "attestation_lookup_unavailable"
    ATTESTATION_RESPONSE_MALFORMED = "attestation_response_malformed"
    SUBJECT_DIGEST_MISMATCH = "subject_digest_mismatch"
    REPOSITORY_IDENTITY_MISMATCH = "repository_identity_mismatch"
    VERIFICATION_NOT_PERFORMED = "verification_not_performed"


# Extension values (bytes)
_WINDOWS_EXE_EXTS = frozenset({".exe", ".msi", ".msix", ".appx", ".bat", ".cmd"})
_SHARED_LIBRARY_EXTS = frozenset({".dll", ".so", ".dylib"})
_DISK_IMAGE_EXTS = frozenset({".dmg", ".iso", ".img", ".vhd", ".vmdk"})
_INSTALLER_EXTS = frozenset({".pkg", ".deb", ".rpm", ".apk"})
_JAVA_ARCHIVE_EXTS = frozenset({".jar", ".war", ".ear", ".aar"})
_PYTHON_WHEEL_EXTS = frozenset({".whl"})
_COMPRESSED_ARCHIVE_EXTS = frozenset({".zip", ".gz", ".bz2", ".xz", ".zst", ".tar", ".7z", ".rar"})
_CHECKSUM_EXTS = frozenset({".sha256", ".sha512", ".md5", ".sha1", ".sha256sum"})
_SIGNATURE_EXTS = frozenset({".asc", ".sig", ".sign", ".gpg", ".pgp"})
_SBOM_EXTS = frozenset({".spdx", ".cyclonedx", ".cdx"})

# Content type prefixes mapped to categories
_CONTENT_TYPE_MAP: tuple[tuple[str, AssetCategory], ...] = (
    ("application/vnd.ms", AssetCategory.WINDOWS_EXE),
    ("application/x-msdownload", AssetCategory.WINDOWS_EXE),
    ("application/x-dosexec", AssetCategory.WINDOWS_EXE),
    ("application/java-archive", AssetCategory.JAVA_ARCHIVE),
    ("application/vnd.android.package", AssetCategory.JAVA_ARCHIVE),
    ("application/x-python-wheel", AssetCategory.PYTHON_WHEEL),
    ("application/zip", AssetCategory.COMPRESSED_ARCHIVE),
    ("application/x-tar", AssetCategory.COMPRESSED_ARCHIVE),
    ("application/gzip", AssetCategory.COMPRESSED_ARCHIVE),
    ("application/x-bzip2", AssetCategory.COMPRESSED_ARCHIVE),
    ("application/x-xz", AssetCategory.COMPRESSED_ARCHIVE),
    ("application/x-7z", AssetCategory.COMPRESSED_ARCHIVE),
    ("application/octet-stream", AssetCategory.UNKNOWN),
)


def classify_asset(name: str, content_type: str) -> AssetCategory:
    """Classifies a release asset into a broad category using name and content_type.

    Uses both extension and content type heuristics. Neither is trusted alone.
    """
    name_lower = name.lower()

    # Source archive produced by GitHub itself
    if name_lower in ("source.tar.gz", "source.zip") or name_lower.endswith(".orig.tar.gz"):
        return AssetCategory.SOURCE_ARCHIVE

    # Check exact-suffix matches for unambiguous types first
    if any(name_lower.endswith(ext) for ext in _CHECKSUM_EXTS):
        return AssetCategory.CHECKSUM
    if any(name_lower.endswith(ext) for ext in _SIGNATURE_EXTS):
        return AssetCategory.SIGNATURE
    if any(name_lower.endswith(ext) for ext in _SBOM_EXTS):
        return AssetCategory.SBOM
    if any(name_lower.endswith(ext) for ext in _JAVA_ARCHIVE_EXTS):
        return AssetCategory.JAVA_ARCHIVE
    if any(name_lower.endswith(ext) for ext in _PYTHON_WHEEL_EXTS):
        return AssetCategory.PYTHON_WHEEL
    # Python sdist: name-version.tar.gz but not source.tar.gz
    if name_lower.endswith(".tar.gz") and (
        name_lower.count("-") >= 1 or name_lower.startswith("dist")
    ):
        return AssetCategory.PYTHON_SDIST
    if any(name_lower.endswith(ext) for ext in _WINDOWS_EXE_EXTS):
        return AssetCategory.WINDOWS_EXE
    if any(name_lower.endswith(ext) for ext in _SHARED_LIBRARY_EXTS):
        return AssetCategory.SHARED_LIBRARY
    if any(name_lower.endswith(ext) for ext in _DISK_IMAGE_EXTS):
        return AssetCategory.DISK_IMAGE
    if any(name_lower.endswith(ext) for ext in _INSTALLER_EXTS):
        return AssetCategory.INSTALLER
    # npm tgz: name starts with typical npm package-name-version.tgz
    if name_lower.endswith(".tgz"):
        return AssetCategory.NODE_PACKAGE
    if any(name_lower.endswith(ext) for ext in _COMPRESSED_ARCHIVE_EXTS):
        return AssetCategory.COMPRESSED_ARCHIVE

    # Fall back to content type heuristics when extension is ambiguous
    ct_lower = content_type.lower()
    for prefix, cat in _CONTENT_TYPE_MAP:
        if prefix in ct_lower:
            return cat

    return AssetCategory.UNKNOWN


@dataclass
class ReleaseAssetRecord:
    """Metadata record for a single GitHub release asset."""

    asset_id: int
    name: str
    label: str
    state: str
    size: int
    content_type: str
    download_count: int
    created_at: datetime
    updated_at: datetime
    uploader_login: str
    browser_download_url: str
    api_download_url: str
    server_digest: str | None = None  # SHA256 if returned by API
    category: AssetCategory = AssetCategory.UNKNOWN
    digest_state: DigestState = DigestState.VERIFICATION_SKIPPED
    calculated_digest: str | None = None
    bytes_processed: int = 0

    def is_binary_or_packaged(self) -> bool:
        """Returns True for asset categories that represent uploadable binary content."""
        return self.category in {
            AssetCategory.WINDOWS_EXE,
            AssetCategory.SHARED_LIBRARY,
            AssetCategory.DISK_IMAGE,
            AssetCategory.INSTALLER,
            AssetCategory.JAVA_ARCHIVE,
            AssetCategory.PYTHON_WHEEL,
            AssetCategory.PYTHON_SDIST,
            AssetCategory.NODE_PACKAGE,
            AssetCategory.COMPRESSED_ARCHIVE,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize asset record to JSON-safe dictionary."""
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "label": self.label,
            "state": self.state,
            "size": self.size,
            "content_type": self.content_type,
            "category": self.category.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "uploader_login": self.uploader_login,
            "browser_download_url": self.browser_download_url,
            "digest_state": self.digest_state.value,
            "server_digest": self.server_digest,
            "calculated_digest": self.calculated_digest,
            "bytes_processed": self.bytes_processed,
        }


@dataclass
class ReleaseRecord:
    """Metadata record for a single GitHub repository release."""

    release_id: int
    name: str
    tag_name: str
    target_commitish: str
    is_draft: bool
    is_prerelease: bool
    created_at: datetime
    published_at: datetime | None
    author_login: str
    body_length: int
    asset_count: int
    source_tarball_url: str
    source_zipball_url: str
    assets: list[ReleaseAssetRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize release record to JSON-safe dictionary."""
        return {
            "release_id": self.release_id,
            "name": self.name,
            "tag_name": self.tag_name,
            "target_commitish": self.target_commitish,
            "is_draft": self.is_draft,
            "is_prerelease": self.is_prerelease,
            "created_at": self.created_at.isoformat(),
            "published_at": self.published_at.isoformat() if self.published_at else None,
            "author_login": self.author_login,
            "body_length": self.body_length,
            "asset_count": self.asset_count,
            "assets": [a.to_dict() for a in self.assets],
        }


@dataclass
class ResolvedRelease:
    """Combines a release record with its resolved Git history mapping."""

    release: ReleaseRecord
    resolved_commit_hash: str | None = None
    local_tag_found: bool = False
    tag_is_annotated: bool = False
    is_reachable_from_default_branch: bool = False
    is_reachable_from_any_ref: bool = False
    resolution_failed: bool = False
    resolution_failure_reason: str = ""
    commits_since_prev: int | None = None
    files_changed_since_prev: int | None = None
    insertions_since_prev: int | None = None
    deletions_since_prev: int | None = None
    prev_resolved_commit: str | None = None
    attestation_state: AttestationState = AttestationState.VERIFICATION_NOT_PERFORMED
    attestation_subject_digest: str | None = None
    attestation_repository: str | None = None
    attestation_workflow: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize resolved release to JSON-safe dictionary."""
        return {
            "release_id": self.release.release_id,
            "name": self.release.name,
            "tag_name": self.release.tag_name,
            "target_commitish": self.release.target_commitish,
            "resolved_commit_hash": self.resolved_commit_hash,
            "local_tag_found": self.local_tag_found,
            "tag_is_annotated": self.tag_is_annotated,
            "is_reachable_from_default_branch": self.is_reachable_from_default_branch,
            "is_reachable_from_any_ref": self.is_reachable_from_any_ref,
            "resolution_failed": self.resolution_failed,
            "resolution_failure_reason": self.resolution_failure_reason,
            "commits_since_prev": self.commits_since_prev,
            "files_changed_since_prev": self.files_changed_since_prev,
            "insertions_since_prev": self.insertions_since_prev,
            "deletions_since_prev": self.deletions_since_prev,
            "attestation_state": self.attestation_state.value,
            "attestation_subject_digest": self.attestation_subject_digest,
            "attestation_repository": self.attestation_repository,
            "attestation_workflow": self.attestation_workflow,
        }


@dataclass
class ReleaseAnalysisResult:
    """Aggregated output from release provenance analysis."""

    releases: list[ResolvedRelease] = field(default_factory=list)
    total_releases: int = 0
    asset_verification_enabled: bool = False
    asset_verification_status: str = "disabled"
    attestation_lookup_enabled: bool = False
    attestation_lookup_status: str = "not_performed"
    incomplete: bool = False
    incomplete_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dictionary."""
        return {
            "total_releases": self.total_releases,
            "asset_verification_enabled": self.asset_verification_enabled,
            "asset_verification_status": self.asset_verification_status,
            "attestation_lookup_enabled": self.attestation_lookup_enabled,
            "attestation_lookup_status": self.attestation_lookup_status,
            "incomplete": self.incomplete,
            "incomplete_reasons": self.incomplete_reasons,
            "releases": [r.to_dict() for r in self.releases],
        }


@dataclass
class AssetVerificationConfig:
    """Typed configuration for bounded asset download and verification."""

    max_asset_size_bytes: int = 100 * 1024 * 1024  # 100 MiB default
    max_total_download_bytes: int = 500 * 1024 * 1024  # 500 MiB default
    max_asset_count: int = 20
    approved_hosts: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "objects.githubusercontent.com",
                "github-production-release-asset-2e65be.s3.amazonaws.com",
                "github.com",
                "api.github.com",
            }
        )
    )
    chunk_size: int = 64 * 1024  # 64 KiB streaming chunks

    def validate(self) -> None:
        """Validate configuration values."""
        if self.max_asset_size_bytes <= 0:
            raise ValueError("max_asset_size_bytes must be positive.")
        if self.max_total_download_bytes <= 0:
            raise ValueError("max_total_download_bytes must be positive.")
        if self.max_asset_count <= 0:
            raise ValueError("max_asset_count must be positive.")
        if self.chunk_size <= 0:
            raise ValueError("chunk_size must be positive.")
