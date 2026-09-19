"""Release provenance analysis: mapping GitHub releases to Git history and verifying assets."""

import hashlib
import logging
import re
import urllib.parse
from bisect import bisect_left
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

import httpx

from gitforensics.compat import UTC, parse_iso_datetime
from gitforensics.release_models import (
    AssetVerificationConfig,
    AttestationState,
    DigestState,
    ReleaseAnalysisResult,
    ReleaseAssetRecord,
    ReleaseRecord,
    ResolvedRelease,
    classify_asset,
)
from gitforensics.security import SecurityLimits, sanitize_text

if TYPE_CHECKING:
    from gitforensics.models import CommitNode, ExtractedHistory, TagNode

logger = logging.getLogger(__name__)


def parse_iso_dt(dt_str: object) -> datetime:
    """Parse an ISO 8601 datetime string to a timezone-aware datetime."""
    return parse_iso_datetime(dt_str)


def parse_release_from_api(
    data: dict[str, Any],
    limits: SecurityLimits | None = None,
    asset_limit: int | None = None,
) -> ReleaseRecord:
    """Constructs a ReleaseRecord from a GitHub API releases response payload."""
    cfg = limits or SecurityLimits()
    raw_assets_value = data.get("assets", [])
    assets_raw = raw_assets_value if isinstance(raw_assets_value, list) else []
    assets: list[ReleaseAssetRecord] = []

    def text(value: object, max_chars: int = 1_024) -> str:
        return (
            sanitize_text(value, max_chars=max_chars, minimize_emails=False)
            if isinstance(value, str)
            else ""
        )

    def integer(value: object) -> int:
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0

    effective_asset_limit = cfg.max_release_assets
    if asset_limit is not None:
        effective_asset_limit = min(cfg.max_release_assets, max(0, asset_limit))
    for a in assets_raw[:effective_asset_limit]:
        if not isinstance(a, dict):
            continue
        uploader_value = a.get("uploader")
        uploader: dict[str, Any] = uploader_value if isinstance(uploader_value, dict) else {}
        name = text(a.get("name"), 1_024)
        ct = text(a.get("content_type"), 256) or "application/octet-stream"
        server_digest_raw = a.get("digest") or None
        # GitHub occasionally returns digest as "sha256:<hex>"
        server_digest: str | None = None
        if server_digest_raw:
            if isinstance(server_digest_raw, str):
                # strip "sha256:" prefix if present
                if server_digest_raw.startswith("sha256:"):
                    server_digest = server_digest_raw[7:]
                else:
                    server_digest = server_digest_raw
                # Basic sanity: SHA-256 hex is 64 chars
                if not re.fullmatch(r"[0-9a-fA-F]{64}", server_digest):
                    server_digest = None  # malformed
                    digest_state = DigestState.DIGEST_MALFORMED
                else:
                    digest_state = DigestState.SERVER_SHA256_AVAILABLE
            else:
                digest_state = DigestState.DIGEST_MALFORMED
        else:
            digest_state = DigestState.DIGEST_MISSING

        asset = ReleaseAssetRecord(
            asset_id=integer(a.get("id")),
            name=name,
            label=text(a.get("label"), 1_024),
            state=text(a.get("state"), 100),
            size=integer(a.get("size")),
            content_type=ct,
            download_count=integer(a.get("download_count")),
            created_at=parse_iso_dt(a.get("created_at")),
            updated_at=parse_iso_dt(a.get("updated_at")),
            uploader_login=text(uploader.get("login"), 100),
            browser_download_url=text(a.get("browser_download_url"), 4_096),
            api_download_url=text(a.get("url"), 4_096),
            server_digest=server_digest,
            category=classify_asset(name, ct),
            digest_state=digest_state,
        )
        assets.append(asset)

    author_value = data.get("author")
    author: dict[str, Any] = author_value if isinstance(author_value, dict) else {}
    body_value = data.get("body")

    return ReleaseRecord(
        release_id=integer(data.get("id")),
        name=text(data.get("name"), 1_024),
        tag_name=text(data.get("tag_name"), 1_024),
        target_commitish=text(data.get("target_commitish"), 1_024),
        is_draft=data.get("draft") is True,
        is_prerelease=data.get("prerelease") is True,
        created_at=parse_iso_dt(data.get("created_at")),
        published_at=parse_iso_dt(data.get("published_at")) if data.get("published_at") else None,
        author_login=text(author.get("login"), 100),
        body_length=min(
            len(body_value) if isinstance(body_value, str) else 0,
            cfg.max_metadata_chars,
        ),
        asset_count=len(assets),
        source_tarball_url=text(data.get("tarball_url"), 4_096),
        source_zipball_url=text(data.get("zipball_url"), 4_096),
        assets=assets,
    )


@dataclass(frozen=True)
class ReleaseResolutionIndex:
    """Commit graph and lookup indexes reused across all releases in one run."""

    tag_by_name: Mapping[str, "TagNode"]
    commit_hashes: frozenset[str]
    sorted_commit_hashes: tuple[str, ...]
    commit_by_hash: Mapping[str, "CommitNode"]
    head_ancestors: frozenset[str]


def collect_commit_ancestors(
    start: str | None, commit_by_hash: Mapping[str, "CommitNode"]
) -> tuple[set[str], bool]:
    """Walk parent edges once per commit, including the tip; flag missing history."""
    ancestors: set[str] = set()
    pending = [start] if start else []
    complete = bool(start)
    while pending:
        commit_hash = pending.pop()
        if commit_hash in ancestors:
            continue
        ancestors.add(commit_hash)
        commit = commit_by_hash.get(commit_hash)
        if commit is None:
            complete = False
            continue
        pending.extend(commit.parents)
    return ancestors, complete


def build_release_resolution_index(history: "ExtractedHistory") -> ReleaseResolutionIndex:
    """Build bounded lookup tables once instead of once per release and detector."""
    commit_hashes = frozenset(commit.hash for commit in history.commits)
    commit_by_hash = {commit.hash: commit for commit in history.commits}
    head_ancestors, _ = collect_commit_ancestors(history.head_commit, commit_by_hash)
    return ReleaseResolutionIndex(
        tag_by_name={tag.short_name: tag for tag in history.tags},
        commit_hashes=commit_hashes,
        sorted_commit_hashes=tuple(sorted(commit_hashes)),
        commit_by_hash=MappingProxyType(commit_by_hash),
        head_ancestors=frozenset(head_ancestors),
    )


def _resolve_hash_prefix(prefix: str, index: ReleaseResolutionIndex) -> str | None:
    """Return a deterministic prefix match without scanning every commit."""
    if prefix in index.commit_hashes:
        return prefix
    position = bisect_left(index.sorted_commit_hashes, prefix)
    if position >= len(index.sorted_commit_hashes):
        return None
    candidate = index.sorted_commit_hashes[position]
    if not candidate.startswith(prefix):
        return None
    next_position = position + 1
    if next_position < len(index.sorted_commit_hashes) and index.sorted_commit_hashes[
        next_position
    ].startswith(prefix):
        return None
    return candidate


def resolve_release_to_history(
    release: ReleaseRecord,
    history: "ExtractedHistory",
    default_branch: str = "main",
    index: ReleaseResolutionIndex | None = None,
) -> ResolvedRelease:
    """Maps a release to its corresponding commit in the extracted history.

    Tries the following resolution strategies in order:
    1. Find matching local TagNode by tag_name.
    2. Walk through annotated tag chain to find the peeled commit.
    3. Fall back to scanning commits for target_commitish prefix match.
    """
    resolved = ResolvedRelease(release=release)
    del default_branch

    resolution_index = index or build_release_resolution_index(history)

    tag = resolution_index.tag_by_name.get(release.tag_name)
    if tag:
        resolved.local_tag_found = True
        resolved.tag_is_annotated = tag.is_annotated

        # Peeled commit hash is the final commit target
        target_hash = tag.peeled_commit_hash or tag.target_hash
        if target_hash and target_hash in resolution_index.commit_hashes:
            resolved.resolved_commit_hash = target_hash
        elif target_hash and target_hash[:7]:
            resolved.resolved_commit_hash = _resolve_hash_prefix(target_hash[:7], resolution_index)
            if not resolved.resolved_commit_hash:
                resolved.resolution_failed = True
                resolved.resolution_failure_reason = (
                    f"Tag '{release.tag_name}' points to object '{target_hash[:12]}...' "
                    "which is not in the extracted commit history "
                    "(history may be shallow or incomplete)."
                )
        else:
            resolved.resolution_failed = True
            resolved.resolution_failure_reason = (
                f"Tag '{release.tag_name}' found but target hash is empty."
            )
    else:
        # No local tag; try target_commitish as a commit prefix
        tc = release.target_commitish
        if tc and len(tc) >= 7:
            resolved.resolved_commit_hash = _resolve_hash_prefix(tc, resolution_index)
            if not resolved.resolved_commit_hash:
                resolved.resolution_failed = True
                resolved.resolution_failure_reason = (
                    f"No local tag found for '{release.tag_name}' and "
                    f"target_commitish '{tc[:12]}...' is not in extracted history."
                )
        else:
            resolved.resolution_failed = True
            resolved.resolution_failure_reason = (
                f"No local tag found for '{release.tag_name}' and "
                f"target_commitish '{tc}' is not a resolvable hash."
            )

    # A fresh remote clone's HEAD is the default branch. Local callers use HEAD.
    if resolved.resolved_commit_hash:
        resolved.is_reachable_from_default_branch = (
            resolved.resolved_commit_hash in resolution_index.head_ancestors
        )
        resolved.is_reachable_from_any_ref = (
            resolved.resolved_commit_hash in resolution_index.commit_hashes
        )

    return resolved


def compute_inter_release_diff(
    resolved_releases: list[ResolvedRelease],
    history: "ExtractedHistory",
    index: ReleaseResolutionIndex | None = None,
) -> list[ResolvedRelease]:
    """Sum per-commit stats for ancestors(current) minus ancestors(previous)."""
    resolution_index = index or build_release_resolution_index(history)

    # Sort by publication timestamp
    pub_sorted = sorted(
        resolved_releases,
        key=lambda r: (
            r.release.published_at or datetime(1970, 1, 1, tzinfo=UTC),
            r.release.release_id,
            r.release.tag_name,
        ),
    )

    previous_ancestors: set[str] = set()
    previous_complete = False
    for i, rr in enumerate(pub_sorted):
        rr.prev_resolved_commit = pub_sorted[i - 1].resolved_commit_hash if i else None
        rr.commits_since_prev = None
        rr.files_changed_since_prev = None
        rr.insertions_since_prev = None
        rr.deletions_since_prev = None
        current_ancestors, current_complete = collect_commit_ancestors(
            rr.resolved_commit_hash, resolution_index.commit_by_hash
        )
        if i and rr.resolved_commit_hash and rr.prev_resolved_commit:
            same_commit = rr.resolved_commit_hash == rr.prev_resolved_commit
            if same_commit or (current_complete and previous_complete):
                added = current_ancestors - previous_ancestors
                commits = [resolution_index.commit_by_hash[commit_hash] for commit_hash in added]
                rr.commits_since_prev = len(commits)
                rr.files_changed_since_prev = sum(commit.changed_files_count for commit in commits)
                rr.insertions_since_prev = sum(commit.insertions for commit in commits)
                rr.deletions_since_prev = sum(commit.deletions for commit in commits)
        # Retain only the adjacent release's ancestry to bound memory usage.
        previous_ancestors, previous_complete = current_ancestors, current_complete

    return pub_sorted


def _validate_download_host(url: str, config: AssetVerificationConfig) -> bool:
    """Returns True if the URL host is within the approved set."""
    try:
        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower()
        return (
            parsed.scheme == "https"
            and host in config.approved_hosts
            and parsed.username is None
            and parsed.password is None
        )
    except Exception:
        return False


def _redact_url_credentials(url: str) -> str:
    """Removes any query parameters that may contain credentials."""
    try:
        parsed = urllib.parse.urlparse(url)
        # Strip query entirely - GitHub signed URLs may include tokens in query params
        return urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", "")
        )
    except Exception:
        return "[INVALID URL]"


def verify_asset_digest(
    asset: ReleaseAssetRecord,
    transport: httpx.BaseTransport | None,
    timeout: float,
    config: AssetVerificationConfig,
    running_total_bytes: list[int],
    verified_count: list[int],
) -> ReleaseAssetRecord:
    """Streams an asset from GitHub and computes its SHA-256 digest.

    Safety guarantees:
    - Only downloads from approved GitHub hosts.
    - Rejects redirects to unapproved hosts.
    - Enforces per-asset and total download byte limits.
    - Never stores the full asset in memory.
    - Never writes the asset to disk.
    - Never extracts archives.
    - Never executes downloaded bytes.
    - Never decompresses data (reads raw bytes only).
    - Cleans up on exception.
    """
    url = asset.browser_download_url or asset.api_download_url
    if not url:
        asset.digest_state = DigestState.DOWNLOAD_FAILED
        return asset

    if not _validate_download_host(url, config):
        logger.warning(
            "Asset download rejected - unapproved host: %s", _redact_url_credentials(url)
        )
        asset.digest_state = DigestState.DOWNLOAD_FAILED
        return asset

    if verified_count[0] >= config.max_asset_count:
        asset.digest_state = DigestState.VERIFICATION_SKIPPED
        return asset

    if running_total_bytes[0] >= config.max_total_download_bytes:
        asset.digest_state = DigestState.VERIFICATION_SKIPPED
        return asset

    # Enforce declared size limit before download
    if asset.size > 0 and asset.size > config.max_asset_size_bytes:
        logger.warning(
            "Asset '%s' declared size %d exceeds limit %d - skipping download.",
            sanitize_text(asset.name),
            asset.size,
            config.max_asset_size_bytes,
        )
        asset.digest_state = DigestState.VERIFICATION_SKIPPED
        return asset

    hasher = hashlib.sha256()
    bytes_read = 0

    try:
        client_kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(timeout, connect=timeout),
            "follow_redirects": False,
        }
        if transport:
            client_kwargs["transport"] = transport

        with httpx.Client(**client_kwargs) as client:
            current_url = url
            response_context: Any | None = None
            for _redirect_count in range(6):
                if not _validate_download_host(current_url, config):
                    asset.digest_state = DigestState.DOWNLOAD_FAILED
                    return asset
                response_context = client.stream(
                    "GET",
                    current_url,
                    headers={"Accept": "*/*", "Accept-Encoding": "identity"},
                )
                response = response_context.__enter__()
                if response.is_redirect:
                    location = response.headers.get("location")
                    response_context.__exit__(None, None, None)
                    response_context = None
                    if not location:
                        asset.digest_state = DigestState.DOWNLOAD_FAILED
                        return asset
                    redirected = urllib.parse.urljoin(current_url, location)
                    if not _validate_download_host(redirected, config):
                        logger.warning("Asset redirect to unapproved host rejected.")
                        asset.digest_state = DigestState.DOWNLOAD_FAILED
                        return asset
                    current_url = redirected
                    continue
                break
            else:
                asset.digest_state = DigestState.DOWNLOAD_FAILED
                return asset

            assert response_context is not None
            try:
                if response.status_code not in (200, 206):
                    asset.digest_state = DigestState.DOWNLOAD_FAILED
                    return asset

                # Check Content-Length header against limits
                cl_header = response.headers.get("content-length")
                if cl_header and cl_header.isdigit():
                    declared_size = int(cl_header)
                    if declared_size > config.max_asset_size_bytes:
                        asset.digest_state = DigestState.VERIFICATION_SKIPPED
                        return asset
                    if running_total_bytes[0] + declared_size > config.max_total_download_bytes:
                        asset.digest_state = DigestState.VERIFICATION_SKIPPED
                        return asset

                # Stream in chunks - never decompress, never store full asset
                for chunk in response.iter_bytes(chunk_size=config.chunk_size):
                    bytes_read += len(chunk)

                    # Per-asset size limit
                    if bytes_read > config.max_asset_size_bytes:
                        logger.warning(
                            "Asset '%s' streamed size exceeded limit at %d bytes.",
                            sanitize_text(asset.name),
                            bytes_read,
                        )
                        asset.digest_state = DigestState.VERIFICATION_SKIPPED
                        asset.bytes_processed = bytes_read
                        return asset

                    # Total download limit
                    if running_total_bytes[0] + bytes_read > config.max_total_download_bytes:
                        logger.warning(
                            "Total download limit reached during asset '%s'.",
                            sanitize_text(asset.name),
                        )
                        asset.digest_state = DigestState.VERIFICATION_SKIPPED
                        asset.bytes_processed = bytes_read
                        return asset

                    hasher.update(chunk)
            finally:
                response_context.__exit__(None, None, None)

    except httpx.TimeoutException:
        logger.warning("Asset download timed out for '%s'.", sanitize_text(asset.name))
        asset.digest_state = DigestState.DOWNLOAD_FAILED
        asset.bytes_processed = bytes_read
        return asset
    except (httpx.NetworkError, httpx.RemoteProtocolError):
        logger.warning("Asset download connection error for '%s'.", sanitize_text(asset.name))
        asset.digest_state = DigestState.DOWNLOAD_FAILED
        asset.bytes_processed = bytes_read
        return asset
    except Exception:
        logger.warning("Asset download failed for '%s'.", sanitize_text(asset.name))
        asset.digest_state = DigestState.DOWNLOAD_FAILED
        asset.bytes_processed = bytes_read
        return asset

    asset.bytes_processed = bytes_read
    asset.calculated_digest = hasher.hexdigest()
    running_total_bytes[0] += bytes_read
    verified_count[0] += 1

    # Compare with server digest if available
    if asset.server_digest:
        if asset.calculated_digest.lower() == asset.server_digest.lower():
            asset.digest_state = DigestState.DOWNLOADED_DIGEST_MATCHED
        else:
            asset.digest_state = DigestState.DOWNLOADED_DIGEST_MISMATCH
    else:
        asset.digest_state = DigestState.DOWNLOADED_DIGEST_MATCHED  # Computed, no reference

    return asset


def lookup_attestation(
    asset: ReleaseAssetRecord,
    owner: str,
    repo: str,
    transport: httpx.BaseTransport | None,
    timeout: float,
    token: str | None,
    api_base_url: str,
    limits: SecurityLimits | None = None,
) -> tuple[AttestationState, str | None, str | None, str | None]:
    """Queries GitHub attestations API for a specific asset digest.

    Returns (state, subject_digest, attested_repo, workflow_ref).
    Only queries if a SHA-256 digest is available.
    Never claims cryptographic verification (metadata-only).
    """
    if not asset.server_digest and not asset.calculated_digest:
        return AttestationState.ATTESTATION_LOOKUP_UNAVAILABLE, None, None, None

    subject_digest = asset.calculated_digest or asset.server_digest
    if not subject_digest:
        return AttestationState.ATTESTATION_LOOKUP_UNAVAILABLE, None, None, None

    cfg = limits or SecurityLimits()
    parsed_base = urllib.parse.urlparse(api_base_url)
    if (
        parsed_base.scheme != "https"
        or (parsed_base.hostname or "").lower() != "api.github.com"
        or parsed_base.username
        or parsed_base.password
    ):
        return AttestationState.ATTESTATION_LOOKUP_UNAVAILABLE, None, None, None
    if not re.fullmatch(r"[0-9a-fA-F]{64}", subject_digest):
        return AttestationState.ATTESTATION_RESPONSE_MALFORMED, None, None, None
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", owner) or not re.fullmatch(
        r"[A-Za-z0-9_.-]{1,100}", repo
    ):
        return AttestationState.ATTESTATION_LOOKUP_UNAVAILABLE, None, None, None
    url = f"{api_base_url.rstrip('/')}/repos/{owner}/{repo}/attestations/sha256:{subject_digest}"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        client_kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(timeout, connect=timeout),
            "follow_redirects": False,
        }
        if transport:
            client_kwargs["transport"] = transport

        with httpx.Client(**client_kwargs) as client:
            with client.stream("GET", url, headers=headers) as streamed:
                if streamed.is_redirect:
                    return AttestationState.ATTESTATION_LOOKUP_UNAVAILABLE, None, None, None
                body = bytearray()
                for chunk in streamed.iter_bytes(64 * 1024):
                    body.extend(chunk)
                    if len(body) > cfg.max_api_response_bytes:
                        return AttestationState.ATTESTATION_RESPONSE_MALFORMED, None, None, None
                resp = httpx.Response(
                    streamed.status_code,
                    headers=streamed.headers,
                    content=bytes(body),
                    request=streamed.request,
                )

        if resp.status_code == 404:
            return AttestationState.NO_ATTESTATION_FOUND, subject_digest, None, None

        if resp.status_code in (401, 403):
            return AttestationState.ATTESTATION_LOOKUP_UNAVAILABLE, None, None, None

        if resp.status_code != 200:
            return AttestationState.ATTESTATION_LOOKUP_UNAVAILABLE, None, None, None

        data = resp.json()
        if not isinstance(data, dict):
            return AttestationState.ATTESTATION_RESPONSE_MALFORMED, None, None, None
        attestations = data.get("attestations", [])
        if not isinstance(attestations, list) or len(attestations) == 0:
            return AttestationState.NO_ATTESTATION_FOUND, subject_digest, None, None

        # Parse first attestation metadata only - no cryptographic verification
        attest = attestations[0]
        if not isinstance(attest, dict):
            return AttestationState.ATTESTATION_RESPONSE_MALFORMED, None, None, None
        bundle_value = attest.get("bundle", {})
        bundle = bundle_value if isinstance(bundle_value, dict) else {}

        # Extract repository identity from predicate
        dsse_value = bundle.get("dsseEnvelope", {})
        dsse_env = dsse_value if isinstance(dsse_value, dict) else {}
        payload_b64 = dsse_env.get("payload", "")
        attested_repo: str | None = None
        raw_attested_repo: str | None = None
        workflow_ref: str | None = None

        max_encoded_payload = ((cfg.max_attestation_payload_bytes + 2) // 3) * 4
        if isinstance(payload_b64, str) and payload_b64 and len(payload_b64) <= max_encoded_payload:
            try:
                import base64
                import json as _json

                missing_padding = len(payload_b64) % 4
                padded_b64 = payload_b64 + ("=" * (4 - missing_padding) if missing_padding else "")
                payload_bytes = base64.b64decode(padded_b64, validate=True)
                if len(payload_bytes) > cfg.max_attestation_payload_bytes:
                    raise ValueError("Attestation payload exceeded the configured limit.")
                payload_json = _json.loads(payload_bytes)
                if not isinstance(payload_json, dict):
                    raise ValueError("Attestation payload is not an object.")
                predicate_value = payload_json.get("predicate", {})
                predicate = predicate_value if isinstance(predicate_value, dict) else {}
                build_value = predicate.get("buildDefinition", {})
                build_def = build_value if isinstance(build_value, dict) else {}
                params_value = build_def.get("externalParameters", {})
                ext_params = params_value if isinstance(params_value, dict) else {}
                workflow_value = ext_params.get("workflow", {})
                workflow = workflow_value if isinstance(workflow_value, dict) else {}
                raw_workflow_ref = workflow.get("ref")
                workflow_ref = (
                    sanitize_text(raw_workflow_ref, max_chars=512)
                    if isinstance(raw_workflow_ref, str)
                    else None
                )
                resolved_dep = build_def.get("resolvedDependencies", [])
                if (
                    resolved_dep
                    and isinstance(resolved_dep, list)
                    and isinstance(resolved_dep[0], dict)
                ):
                    raw_repo = resolved_dep[0].get("uri")
                    raw_attested_repo = raw_repo if isinstance(raw_repo, str) else None
                    attested_repo = (
                        sanitize_text(raw_repo, max_chars=2_048)
                        if isinstance(raw_repo, str)
                        else None
                    )
            except (ValueError, TypeError, UnicodeError):
                return AttestationState.ATTESTATION_RESPONSE_MALFORMED, None, None, None

        expected_repo = f"https://github.com/{owner}/{repo}"
        if raw_attested_repo is None:
            return AttestationState.ATTESTATION_RESPONSE_MALFORMED, None, None, None
        if expected_repo.casefold() != raw_attested_repo.rstrip("/").casefold():
            return (
                AttestationState.REPOSITORY_IDENTITY_MISMATCH,
                subject_digest,
                attested_repo,
                workflow_ref,
            )

        return (
            AttestationState.MATCHING_ATTESTATION_FOUND,
            subject_digest,
            attested_repo,
            workflow_ref,
        )

    except (httpx.HTTPError, ValueError, TypeError):
        logger.warning("Attestation lookup failed safely.")
        return AttestationState.ATTESTATION_LOOKUP_UNAVAILABLE, None, None, None


def run_release_analysis(
    releases: list[ReleaseRecord],
    history: "ExtractedHistory",
    owner: str,
    repo: str,
    default_branch: str = "main",
    verify_assets: bool = False,
    asset_config: AssetVerificationConfig | None = None,
    transport: httpx.BaseTransport | None = None,
    timeout: float = 10.0,
    token: str | None = None,
    api_base_url: str = "https://api.github.com",
    limits: SecurityLimits | None = None,
) -> ReleaseAnalysisResult:
    """Runs release provenance resolution and optional asset verification.

    This function:
    1. Skips draft releases from public analysis.
    2. Resolves each release to Git history.
    3. Computes inter-release diffs.
    4. Optionally streams assets for SHA-256 digest verification.
    5. Queries attestation API if digest is available.
    6. Returns a fully typed ReleaseAnalysisResult.
    """
    cfg = asset_config or AssetVerificationConfig()
    cfg.validate()
    security_limits = limits or SecurityLimits()
    security_limits.validate()

    result = ReleaseAnalysisResult(
        asset_verification_enabled=verify_assets,
        attestation_lookup_enabled=False,
    )

    if len(releases) > security_limits.max_releases:
        result.incomplete = True
        result.incomplete_reasons.append("Release analysis reached the configured release limit.")

    # Only analyze non-draft public releases
    public_releases = [r for r in releases[: security_limits.max_releases] if not r.is_draft]
    result.total_releases = len(public_releases)

    if not public_releases:
        result.asset_verification_status = "no_releases"
        result.attestation_lookup_status = "no_releases"
        return result

    resolution_index = build_release_resolution_index(history)
    resolved_list: list[ResolvedRelease] = []
    for release in public_releases:
        rr = resolve_release_to_history(
            release,
            history,
            default_branch=default_branch,
            index=resolution_index,
        )
        resolved_list.append(rr)

    # Compute inter-release diffs
    resolved_list = compute_inter_release_diff(resolved_list, history, index=resolution_index)
    if any(rr.commits_since_prev is None for rr in resolved_list[1:]):
        result.incomplete = True
        result.incomplete_reasons.append(
            "One or more release deltas are unavailable because commit ancestry is incomplete."
        )

    # Bounded asset verification
    running_total_bytes: list[int] = [0]
    verified_count: list[int] = [0]
    verification_limit_recorded = False
    attestation_incomplete_recorded = False

    for rr in resolved_list:
        for asset in rr.release.assets:
            if verify_assets:
                # Skip source archives (GitHub-generated, not maintainer-uploaded)
                from gitforensics.release_models import AssetCategory

                if asset.category == AssetCategory.SOURCE_ARCHIVE:
                    asset.digest_state = DigestState.VERIFICATION_SKIPPED
                    continue

                if (
                    verified_count[0] >= cfg.max_asset_count
                    or running_total_bytes[0] >= cfg.max_total_download_bytes
                ):
                    asset.digest_state = DigestState.VERIFICATION_SKIPPED
                else:
                    asset = verify_asset_digest(
                        asset=asset,
                        transport=transport,
                        timeout=timeout,
                        config=cfg,
                        running_total_bytes=running_total_bytes,
                        verified_count=verified_count,
                    )
                if (
                    asset.digest_state == DigestState.VERIFICATION_SKIPPED
                    and not verification_limit_recorded
                ):
                    result.incomplete = True
                    result.incomplete_reasons.append(
                        "Asset verification omitted one or more assets due to configured limits."
                    )
                    verification_limit_recorded = True

                # Attestation lookup when we have a digest
                if asset.calculated_digest or asset.server_digest:
                    attest_state, subj_dig, attest_repo, wf_ref = lookup_attestation(
                        asset=asset,
                        owner=owner,
                        repo=repo,
                        transport=transport,
                        timeout=timeout,
                        token=token,
                        api_base_url=api_base_url,
                        limits=security_limits,
                    )
                    rr.attestation_state = attest_state
                    rr.attestation_subject_digest = subj_dig
                    rr.attestation_repository = attest_repo
                    rr.attestation_workflow = wf_ref
                    result.attestation_lookup_enabled = True
                    if (
                        attest_state
                        in {
                            AttestationState.ATTESTATION_LOOKUP_UNAVAILABLE,
                            AttestationState.ATTESTATION_RESPONSE_MALFORMED,
                        }
                        and not attestation_incomplete_recorded
                    ):
                        result.incomplete = True
                        result.incomplete_reasons.append(
                            "One or more attestation lookups were unavailable or malformed."
                        )
                        attestation_incomplete_recorded = True
            else:
                asset.digest_state = DigestState.VERIFICATION_SKIPPED

    result.releases = resolved_list
    result.asset_verification_status = (
        f"completed ({verified_count[0]} assets, {running_total_bytes[0]} bytes)"
        if verify_assets
        else "disabled"
    )
    result.attestation_lookup_status = (
        "performed" if result.attestation_lookup_enabled else "not_performed"
    )
    result.incomplete_reasons = sorted(set(result.incomplete_reasons))

    return result
