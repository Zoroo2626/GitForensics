"""Core data models for GitForensics."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

from gitforensics import __version__
from gitforensics.compat import UTC, StrEnum
from gitforensics.security import SecurityLimits, sanitize_path, sanitize_text, sanitize_value


class Severity(StrEnum):
    """Severity levels for findings."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(StrEnum):
    """Confidence levels for findings."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class OutputFormat(StrEnum):
    """Output format choices for CLI report."""

    TEXT = "text"
    TERMINAL = "terminal"
    JSON = "json"


class FailOnLevel(StrEnum):
    """Fail-on severity threshold options."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RepositoryInputType(StrEnum):
    """Type of repository input."""

    LOCAL = "local"
    REMOTE = "remote"


class SignatureStatus(StrEnum):
    """Git commit signature verification status."""

    VALID = "VALID"
    BAD = "BAD"
    UNKNOWN_TRUST = "UNKNOWN_TRUST"
    EXPIRED_SIGNATURE = "EXPIRED_SIGNATURE"
    EXPIRED_KEY = "EXPIRED_KEY"
    REVOKED_KEY = "REVOKED_KEY"
    VERIFICATION_ERROR = "VERIFICATION_ERROR"
    UNSIGNED = "UNSIGNED"
    UNKNOWN = "UNKNOWN"


class RepositoryConsistencyStatus(StrEnum):
    """Typed outcome of the lightweight local repository consistency check."""

    NOT_CHECKED = "not_checked"
    STABLE = "stable"
    CHANGED = "changed"
    CHECK_FAILED = "check_failed"
    MARKER_TRUNCATED = "marker_truncated"


def sanitize_path_str(path_str: str) -> str:
    """Sanitizes path strings to remove temporary clone directory prefixes."""
    if not path_str:
        return path_str
    cleaned = re.sub(
        r".*?(gitforensics_clone_[a-zA-Z0-9_-]+|pytest-of-[a-zA-Z0-9_-]+)[/\\]?",
        "<REMOTE_REPOSITORY>/",
        path_str,
    )
    return sanitize_path(cleaned)


@dataclass(frozen=True)
class RepositoryInput:
    """Represents a repository input string (path or remote URL)."""

    raw_input: str
    input_type: RepositoryInputType
    resolved_path_or_url: str


@dataclass(frozen=True)
class CommitNode:
    """Structured representation of a parsed Git commit."""

    hash: str
    parents: list[str]
    author_name: str
    author_email: str
    author_date: datetime
    committer_name: str
    committer_email: str
    committer_date: datetime
    subject: str
    body: str
    tree_hash: str
    changed_files_count: int = 0
    insertions: int = 0
    deletions: int = 0
    signature_status: SignatureStatus = SignatureStatus.UNSIGNED

    @property
    def is_root(self) -> bool:
        """Returns True if this commit has no parents."""
        return len(self.parents) == 0

    @property
    def is_merge(self) -> bool:
        """Returns True if this commit has multiple parents."""
        return len(self.parents) > 1

    def to_dict(self) -> dict[str, Any]:
        """Serialize CommitNode to JSON-serializable dictionary."""
        return {
            "hash": self.hash,
            "parents": self.parents,
            "author_name": self.author_name,
            "author_email": self.author_email,
            "author_date": self.author_date.isoformat(),
            "committer_name": self.committer_name,
            "committer_email": self.committer_email,
            "committer_date": self.committer_date.isoformat(),
            "subject": self.subject,
            "body": self.body,
            "tree_hash": self.tree_hash,
            "changed_files_count": self.changed_files_count,
            "insertions": self.insertions,
            "deletions": self.deletions,
            "signature_status": self.signature_status.value,
            "is_root": self.is_root,
            "is_merge": self.is_merge,
        }


@dataclass
class TagNode:
    """Structured representation of a Git tag reference."""

    ref_name: str
    short_name: str
    target_hash: str
    target_type: str
    peeled_commit_hash: str | None = None
    is_annotated: bool = False
    tagger_name: str = ""
    tagger_email: str = ""
    tagger_date: datetime | None = None
    message: str = ""
    signature_status: SignatureStatus = SignatureStatus.UNSIGNED
    commit_date: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize TagNode to dictionary."""
        return {
            "ref_name": self.ref_name,
            "short_name": self.short_name,
            "target_hash": self.target_hash,
            "target_type": self.target_type,
            "peeled_commit_hash": self.peeled_commit_hash,
            "is_annotated": self.is_annotated,
            "tagger_name": self.tagger_name,
            "tagger_email": self.tagger_email,
            "tagger_date": self.tagger_date.isoformat() if self.tagger_date else None,
            "message": self.message,
            "signature_status": self.signature_status.value,
            "commit_date": self.commit_date.isoformat() if self.commit_date else None,
        }


@dataclass
class WorkflowFile:
    """Metadata and safe line content for a GitHub Actions workflow file."""

    path: str
    name: str | None
    content: str
    lines: list[str] = field(default_factory=list)
    triggers: list[str] = field(default_factory=list)
    schedules: list[str] = field(default_factory=list)
    permissions: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize WorkflowFile metadata."""
        return {
            "path": sanitize_path_str(self.path),
            "name": self.name,
            "triggers": self.triggers,
            "schedules": self.schedules,
            "permissions": self.permissions,
        }


@dataclass
class GitHubMetadata:
    """Typed container for metadata fetched from the GitHub REST API."""

    owner: str
    name: str
    repo_id: int
    created_at: datetime
    updated_at: datetime
    pushed_at: datetime
    default_branch: str
    visibility: str
    archived: bool
    disabled: bool
    is_fork: bool
    parent_owner: str | None = None
    parent_name: str | None = None
    size: int = 0
    open_issues_count: int = 0
    stargazers_count: int = 0
    forks_count: int = 0
    watchers_count: int = 0
    language: str | None = None
    license: str | None = None
    topics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize GitHubMetadata to dictionary."""
        return {
            "owner": self.owner,
            "name": self.name,
            "repo_id": self.repo_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "pushed_at": self.pushed_at.isoformat(),
            "default_branch": self.default_branch,
            "visibility": self.visibility,
            "archived": self.archived,
            "disabled": self.disabled,
            "is_fork": self.is_fork,
            "parent_owner": self.parent_owner,
            "parent_name": self.parent_name,
            "size": self.size,
            "open_issues_count": self.open_issues_count,
            "stargazers_count": self.stargazers_count,
            "forks_count": self.forks_count,
            "watchers_count": self.watchers_count,
            "language": self.language,
            "license": self.license,
            "topics": self.topics,
        }


@dataclass
class ExtractedHistory:
    """Container for extracted repository history, tags, and metadata."""

    repository_path: str
    git_dir: str
    is_bare: bool
    head_commit: str | None
    commits: list[CommitNode] = field(default_factory=list)
    tags: list[TagNode] = field(default_factory=list)
    workflows: list[WorkflowFile] = field(default_factory=list)
    is_limited: bool = False
    limit_reason: str = ""
    warnings: list[str] = field(default_factory=list)
    state_marker_start: RepositoryStateMarker | None = field(default=None, repr=False)
    consistency_status: RepositoryConsistencyStatus = RepositoryConsistencyStatus.NOT_CHECKED

    def to_dict(self) -> dict[str, Any]:
        """Serialize ExtractedHistory to dictionary."""
        return {
            "repository_path": sanitize_path_str(self.repository_path),
            "git_dir": sanitize_path_str(self.git_dir),
            "is_bare": self.is_bare,
            "head_commit": self.head_commit,
            "total_commits": len(self.commits),
            "total_tags": len(self.tags),
            "total_workflows": len(self.workflows),
            "is_limited": self.is_limited,
            "limit_reason": self.limit_reason,
            "warnings": [sanitize_text(w) for w in self.warnings],
            "consistency_status": self.consistency_status.value,
            "commits": [c.to_dict() for c in self.commits],
            "tags": [t.to_dict() for t in self.tags],
            "workflows": [w.to_dict() for w in self.workflows],
        }


@dataclass(frozen=True)
class RepositoryStateMarker:
    """Bounded identity of repository state relevant to one local analysis run."""

    head_commit: str | None
    refs_digest: str
    ref_count: int
    git_dir_identity: str
    is_bare: bool
    refs_truncated: bool = False
    workflow_digest: str = ""
    workflow_file_count: int = 0
    workflows_truncated: bool = False


@dataclass(frozen=True)
class AnalysisSummary:
    """Immutable, per-run indexes and statistics shared by independent detectors."""

    commits_by_author_date: tuple[CommitNode, ...]
    commits_by_committer_date: tuple[CommitNode, ...]
    non_merge_commits_by_author_date: tuple[CommitNode, ...]
    commit_by_hash: Mapping[str, CommitNode]
    commit_index_by_hash: Mapping[str, int]
    root_commits: tuple[CommitNode, ...]
    normalized_author_identities: tuple[str, ...]
    normalized_committer_identities: tuple[str, ...]
    author_counts: tuple[tuple[str, int], ...]
    total_changed_files: int
    total_insertions: int
    total_deletions: int
    earliest_committer_date: datetime | None
    latest_committer_date: datetime | None
    tags_by_target: Mapping[str, tuple[TagNode, ...]]
    tags_by_name: Mapping[str, TagNode]


@dataclass
class RepositoryContext:
    """Context passed to detectors with history and optional GitHub metadata."""

    input: RepositoryInput
    history: ExtractedHistory
    github_token: str | None = None
    github_metadata: GitHubMetadata | None = None
    offline: bool = False
    release_analysis_result: Any | None = None
    security_limits: SecurityLimits = field(default_factory=SecurityLimits)
    analysis_summary: AnalysisSummary | None = field(default=None, repr=False)


@dataclass(frozen=True)
class Evidence:
    """Concrete evidence supporting a finding."""

    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, limits: SecurityLimits | None = None) -> dict[str, Any]:
        """Return bounded, recursively sanitized evidence data."""
        result = sanitize_value(self.data, limits=limits)
        return result if isinstance(result, dict) else {"value": result}


@dataclass(frozen=True)
class Finding:
    """An observable anomaly found during repository analysis."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    evidence: Evidence

    @property
    def fingerprint(self) -> str:
        """Return a stable internal fingerprint without extending the report schema."""
        payload = {
            "rule_id": sanitize_text(self.rule_id, max_chars=32, minimize_emails=False),
            "title": sanitize_text(self.title, max_chars=512),
            "description": sanitize_text(self.description, max_chars=2_048),
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "evidence": self.evidence.to_dict(),
        }
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass
class RiskScore:
    """Transparent risk score calculation model."""

    score: int
    base_score: int
    formula: str
    details: str = ""


@dataclass
class DetectorResult:
    """Results returned by an individual detector execution."""

    rule_id: str
    findings: list[Finding] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    truncated: bool = False
    truncation_reason: str = ""


@dataclass
class AnalysisReport:
    """Aggregated report containing all findings and risk scoring."""

    schema_version: str = "1.0.0"
    gitforensics_version: str = __version__
    repository: str = ""
    input_type: str = "local"
    scan_timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    duration_seconds: float = 0.0
    head_commit: str | None = None
    total_commits: int = 0
    total_contributors: int = 0
    total_tags: int = 0
    total_workflows: int = 0
    github_metadata_available: bool = False
    is_complete: bool = True
    assessment_label: str = "Low observed concern"
    risk_score: int = 0
    scoring_breakdown: dict[str, Any] = field(default_factory=dict)
    score_explanation: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    skipped_detectors: list[str] = field(default_factory=list)
    failed_detectors: list[str] = field(default_factory=list)
    incomplete_analysis_reasons: list[str] = field(default_factory=list)
    total_releases: int = 0
    release_analysis: dict[str, Any] | None = None
    security_limits: SecurityLimits = field(default_factory=SecurityLimits, repr=False)

    def to_dict(self) -> dict[str, Any]:
        """Serialize report to JSON-serializable dictionary."""
        effective_breakdown = self.scoring_breakdown or self.score_explanation
        report_limits = replace(
            self.security_limits,
            max_evidence_items=max(
                self.security_limits.max_evidence_items,
                self.security_limits.max_findings,
                self.security_limits.max_releases,
                self.security_limits.max_release_assets,
            ),
        )
        safe_breakdown = sanitize_value(effective_breakdown, limits=report_limits)
        safe_release = sanitize_value(self.release_analysis, limits=report_limits)
        safe_reasons = sanitize_value(self.incomplete_analysis_reasons, limits=report_limits)
        if not isinstance(safe_reasons, list):
            safe_reasons = []
        findings = self.findings[: self.security_limits.max_findings]
        report_was_truncated = len(findings) < len(self.findings)
        if report_was_truncated:
            safe_reasons.append("Report findings reached the configured output limit.")

        return {
            "schema_version": sanitize_text(self.schema_version, max_chars=32),
            "gitforensics_version": sanitize_text(self.gitforensics_version, max_chars=32),
            "repository": sanitize_path_str(self.repository),
            "input_type": sanitize_text(self.input_type, max_chars=32),
            "scan_timestamp": sanitize_text(self.scan_timestamp, max_chars=64),
            "duration_seconds": round(self.duration_seconds, 3),
            "head_commit": sanitize_text(self.head_commit, max_chars=128)
            if self.head_commit
            else None,
            "total_commits": self.total_commits,
            "total_contributors": self.total_contributors,
            "total_tags": self.total_tags,
            "total_workflows": self.total_workflows,
            "github_metadata_available": self.github_metadata_available,
            "is_complete": self.is_complete and not report_was_truncated,
            "assessment_label": sanitize_text(self.assessment_label, max_chars=128),
            "risk_score": self.risk_score,
            "scoring_breakdown": safe_breakdown,
            "score_explanation": safe_breakdown,
            "incomplete_analysis_reasons": safe_reasons,
            "skipped_detectors": sanitize_value(self.skipped_detectors, limits=report_limits),
            "failed_detectors": sanitize_value(self.failed_detectors, limits=report_limits),
            "total_releases": self.total_releases,
            "release_analysis": safe_release,
            "findings": [
                {
                    "rule_id": sanitize_text(f.rule_id, max_chars=32, minimize_emails=False),
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "title": sanitize_text(f.title, max_chars=512),
                    "description": sanitize_text(f.description, max_chars=2_048),
                    "evidence": f.evidence.to_dict(limits=self.security_limits),
                }
                for f in findings
            ],
        }
