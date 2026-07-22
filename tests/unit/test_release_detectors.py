"""Unit tests for release provenance detectors GF011 through GF016."""

from datetime import datetime

from gitforensics.compat import UTC
from gitforensics.detectors.remote.release_provenance import (
    AssetDigestAndAttestationDetector,
    AssetHeavyMinimalSourceDetector,
    MutableReleaseAssetDetector,
    ReleaseChronologyConflictDetector,
    ReleaseUnresolvableDetector,
    RepeatedReleaseTargetsDetector,
)
from gitforensics.models import (
    ExtractedHistory,
    RepositoryContext,
    RepositoryInput,
    RepositoryInputType,
    Severity,
)
from gitforensics.release_analysis import parse_release_from_api
from gitforensics.release_models import (
    AttestationState,
    DigestState,
    ReleaseAnalysisResult,
    ResolvedRelease,
)
from tests.helpers.git_fixtures import make_synthetic_commit


def _make_context(
    commits=None,
    tags=None,
    release_analysis_result=None,
    offline: bool = False,
    history_is_limited: bool = False,
) -> RepositoryContext:
    """Build a minimal RepositoryContext with optional release analysis result."""
    commits = commits or []
    inp = RepositoryInput(
        raw_input="/synthetic",
        input_type=RepositoryInputType.LOCAL,
        resolved_path_or_url="/synthetic",
    )
    history = ExtractedHistory(
        repository_path="/synthetic",
        git_dir=".git",
        is_bare=False,
        head_commit=commits[0].hash if commits else None,
        commits=commits,
        tags=tags or [],
        is_limited=history_is_limited,
    )
    ctx = RepositoryContext(input=inp, history=history, offline=offline)
    ctx.release_analysis_result = release_analysis_result  # type: ignore[attr-defined]
    return ctx


def _make_resolved(
    release_id: int = 1,
    name: str = "v1.0.0",
    tag_name: str = "v1.0.0",
    published_at: datetime | None = None,
    resolved_commit: str | None = "abc" + "0" * 37,
    resolution_failed: bool = False,
    failure_reason: str = "",
    commits_since_prev: int | None = None,
    files_changed: int | None = None,
    assets: list | None = None,
    insertions: int | None = None,
    deletions: int | None = None,
) -> ResolvedRelease:
    """Build a ResolvedRelease for testing."""
    pub = published_at or datetime(2026, 1, 1, tzinfo=UTC)
    assets_list = assets or []

    release_data = {
        "id": release_id,
        "name": name,
        "tag_name": tag_name,
        "target_commitish": "main",
        "draft": False,
        "prerelease": False,
        "created_at": pub.isoformat(),
        "published_at": pub.isoformat(),
        "author": {"login": "octocat"},
        "body": "",
        "tarball_url": "",
        "zipball_url": "",
        "assets": assets_list,
    }
    release = parse_release_from_api(release_data)

    rr = ResolvedRelease(
        release=release,
        resolved_commit_hash=resolved_commit,
        resolution_failed=resolution_failed,
        resolution_failure_reason=failure_reason,
        commits_since_prev=commits_since_prev,
        files_changed_since_prev=files_changed,
        insertions_since_prev=insertions,
        deletions_since_prev=deletions,
    )
    return rr


def _analysis_result(releases: list[ResolvedRelease]) -> ReleaseAnalysisResult:
    return ReleaseAnalysisResult(
        releases=releases,
        total_releases=len(releases),
    )


# ---------------------------------------------------------------------------
# GF011: ReleaseUnresolvableDetector
# ---------------------------------------------------------------------------


def test_gf011_no_releases_skipped() -> None:
    """GF011: Skipped when no release analysis is available."""
    ctx = _make_context()
    result = ReleaseUnresolvableDetector().analyze(ctx)
    assert result.skipped


def test_gf011_all_resolved_no_findings() -> None:
    """GF011: No findings when all releases are resolved."""
    rr = _make_resolved(resolved_commit="abc" + "0" * 37, resolution_failed=False)
    ctx = _make_context(release_analysis_result=_analysis_result([rr]))
    result = ReleaseUnresolvableDetector().analyze(ctx)
    assert not result.skipped
    assert len(result.findings) == 0


def test_gf011_unresolvable_release_produces_finding() -> None:
    """GF011: Reports finding when a release cannot be resolved."""
    rr = _make_resolved(
        resolved_commit=None,
        resolution_failed=True,
        failure_reason="Tag not found",
    )
    ctx = _make_context(release_analysis_result=_analysis_result([rr]))
    result = ReleaseUnresolvableDetector().analyze(ctx)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "GF011"
    assert f.severity == Severity.MEDIUM
    assert "v1.0.0" in f.description or "v1.0.0" in str(f.evidence.data)


def test_gf011_incomplete_history_uses_conservative_severity() -> None:
    """GF011: Uses LOW severity when history is incomplete."""
    rr = _make_resolved(
        resolved_commit=None,
        resolution_failed=True,
        failure_reason="Shallow history",
    )
    ctx = _make_context(
        release_analysis_result=_analysis_result([rr]),
        history_is_limited=True,
    )
    result = ReleaseUnresolvableDetector().analyze(ctx)
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.LOW


# ---------------------------------------------------------------------------
# GF012: RepeatedReleaseTargetsDetector
# ---------------------------------------------------------------------------


def test_gf012_three_releases_same_commit_triggers() -> None:
    """GF012: Flags 3+ releases targeting the same commit."""
    shared = "deadbeef" + "0" * 32
    releases = [
        _make_resolved(release_id=i, name=f"v1.0.{i}", tag_name=f"v1.0.{i}", resolved_commit=shared)
        for i in range(3)
    ]
    ctx = _make_context(release_analysis_result=_analysis_result(releases))
    result = RepeatedReleaseTargetsDetector().analyze(ctx)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "GF012"
    assert f.severity == Severity.MEDIUM
    assert "3" in str(f.evidence.data.get("release_count"))


def test_gf012_two_releases_same_commit_no_finding() -> None:
    """GF012: Does not flag 2 releases on the same commit (below threshold)."""
    shared = "deadbeef" + "0" * 32
    releases = [
        _make_resolved(release_id=i, name=f"v1.0.{i}", tag_name=f"v1.0.{i}", resolved_commit=shared)
        for i in range(2)
    ]
    ctx = _make_context(release_analysis_result=_analysis_result(releases))
    result = RepeatedReleaseTargetsDetector().analyze(ctx)
    assert len(result.findings) == 0


def test_gf012_releases_different_commits_no_finding() -> None:
    """GF012: No finding when releases target different commits."""
    releases = [
        _make_resolved(release_id=i, name=f"v1.0.{i}", resolved_commit=f"commit{i}" + "0" * 33)
        for i in range(5)
    ]
    ctx = _make_context(release_analysis_result=_analysis_result(releases))
    result = RepeatedReleaseTargetsDetector().analyze(ctx)
    assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# GF013: ReleaseChronologyConflictDetector
# ---------------------------------------------------------------------------


def test_gf013_version_regression_produces_finding() -> None:
    """GF013: Reports finding when higher-version release published before lower-version."""
    older_date = datetime(2026, 1, 1, tzinfo=UTC)
    newer_date = datetime(2026, 2, 1, tzinfo=UTC)

    # v2.0.0 published first, then v1.0.0 published later = chronology conflict
    rr1 = _make_resolved(release_id=1, name="v2.0.0", tag_name="v2.0.0", published_at=older_date)
    rr2 = _make_resolved(release_id=2, name="v1.0.0", tag_name="v1.0.0", published_at=newer_date)
    ctx = _make_context(release_analysis_result=_analysis_result([rr1, rr2]))
    result = ReleaseChronologyConflictDetector().analyze(ctx)
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "GF013"


def test_gf013_correct_version_order_no_finding() -> None:
    """GF013: No finding for correct ascending version order."""
    older = datetime(2026, 1, 1, tzinfo=UTC)
    newer = datetime(2026, 2, 1, tzinfo=UTC)

    rr1 = _make_resolved(release_id=1, name="v1.0.0", published_at=older)
    rr2 = _make_resolved(release_id=2, name="v2.0.0", published_at=newer)
    ctx = _make_context(release_analysis_result=_analysis_result([rr1, rr2]))
    result = ReleaseChronologyConflictDetector().analyze(ctx)
    assert len(result.findings) == 0


def test_gf013_nonsemantic_names_skipped() -> None:
    """GF013: Non-semver release names are skipped without producing findings."""
    older = datetime(2026, 1, 1, tzinfo=UTC)
    newer = datetime(2026, 2, 1, tzinfo=UTC)

    rr1 = _make_resolved(release_id=1, name="Stable Release", published_at=older)
    rr2 = _make_resolved(release_id=2, name="Alpha Preview", published_at=newer)
    ctx = _make_context(release_analysis_result=_analysis_result([rr1, rr2]))
    result = ReleaseChronologyConflictDetector().analyze(ctx)
    assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# GF014: AssetHeavyMinimalSourceDetector
# ---------------------------------------------------------------------------


def _make_asset_payload(
    name: str, size: int, content_type: str = "application/octet-stream"
) -> dict:
    return {
        "id": hash(name) & 0xFFFF,
        "name": name,
        "label": "",
        "state": "uploaded",
        "size": size,
        "content_type": content_type,
        "download_count": 0,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "uploader": {"login": "bot"},
        "browser_download_url": f"https://github.com/o/r/releases/download/v1/{name}",
        "url": f"https://api.github.com/repos/o/r/releases/assets/{hash(name) & 0xFFFF}",
    }


def test_gf014_first_release_large_binary_produces_info() -> None:
    """GF014: First release with large binary produces INFO contextual finding."""
    rr = _make_resolved(
        name="v1.0.0",
        commits_since_prev=None,  # First release
        assets=[_make_asset_payload("app.exe", 2 * 1024 * 1024)],  # 2 MiB
    )
    ctx = _make_context(release_analysis_result=_analysis_result([rr]))
    result = AssetHeavyMinimalSourceDetector().analyze(ctx)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_gf014_subsequent_release_heavy_assets_minimal_source() -> None:
    """GF014: Subsequent release with heavy assets and minimal source change is flagged."""
    rr = _make_resolved(
        name="v2.0.0",
        commits_since_prev=1,  # Only 1 commit since last release
        files_changed=2,
        assets=[_make_asset_payload("app.exe", 10 * 1024 * 1024)],  # 10 MiB
    )
    ctx = _make_context(release_analysis_result=_analysis_result([rr]))
    result = AssetHeavyMinimalSourceDetector().analyze(ctx)
    assert len(result.findings) >= 1
    f = result.findings[0]
    assert f.severity == Severity.LOW
    assert "v2.0.0" in f.description


def test_gf014_release_with_only_checksums_no_finding() -> None:
    """GF014: Release with only checksum/signature files does not trigger heavy-asset rule."""
    rr = _make_resolved(
        name="v1.1.0",
        commits_since_prev=0,
        files_changed=1,
        assets=[
            _make_asset_payload("checksums.sha256", 500),
            _make_asset_payload("release.asc", 1000),
        ],
    )
    ctx = _make_context(release_analysis_result=_analysis_result([rr]))
    result = AssetHeavyMinimalSourceDetector().analyze(ctx)
    assert len(result.findings) == 0


def test_gf014_substantial_source_changes_no_finding() -> None:
    """GF014: Heavy binary release with substantial source changes does not trigger."""
    rr = _make_resolved(
        name="v3.0.0",
        commits_since_prev=50,  # Many commits
        files_changed=200,
        assets=[_make_asset_payload("app.exe", 5 * 1024 * 1024)],
    )
    ctx = _make_context(release_analysis_result=_analysis_result([rr]))
    result = AssetHeavyMinimalSourceDetector().analyze(ctx)
    assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# GF015: MutableReleaseAssetDetector
# ---------------------------------------------------------------------------


def test_gf015_asset_created_substantially_after_release() -> None:
    """GF015: Asset created more than 1 hour after release publication is flagged."""
    rr = _make_resolved(
        name="v1.0.0",
        published_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
        assets=[
            {
                "id": 1,
                "name": "new_asset.zip",
                "label": "",
                "state": "uploaded",
                "size": 1024,
                "content_type": "application/zip",
                "download_count": 0,
                "created_at": "2026-01-01T04:00:00Z",  # 4 hours after pub
                "updated_at": "2026-01-01T04:00:00Z",
                "uploader": {"login": "bot"},
                "browser_download_url": "https://github.com/o/r/releases/download/v1/new.zip",
                "url": "https://api.github.com/repos/o/r/releases/assets/1",
            }
        ],
    )
    ctx = _make_context(release_analysis_result=_analysis_result([rr]))
    result = MutableReleaseAssetDetector().analyze(ctx)
    assert len(result.findings) >= 1
    f = result.findings[0]
    assert f.rule_id == "GF015"
    assert "after" in f.description.lower()


def test_gf015_asset_updated_same_time_no_finding() -> None:
    """GF015: Asset with updated_at == created_at close to publication does not trigger."""
    rr = _make_resolved(
        name="v1.0.0",
        published_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
        assets=[
            {
                "id": 1,
                "name": "ok.zip",
                "label": "",
                "state": "uploaded",
                "size": 100,
                "content_type": "application/zip",
                "download_count": 0,
                "created_at": "2026-01-01T00:10:00Z",  # 10 min after pub - within threshold
                "updated_at": "2026-01-01T00:10:00Z",
                "uploader": {"login": "bot"},
                "browser_download_url": "https://github.com/o/r/releases/download/v1/ok.zip",
                "url": "https://api.github.com/repos/o/r/releases/assets/1",
            }
        ],
    )
    ctx = _make_context(release_analysis_result=_analysis_result([rr]))
    result = MutableReleaseAssetDetector().analyze(ctx)
    assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# GF016: AssetDigestAndAttestationDetector
# ---------------------------------------------------------------------------


def test_gf016_digest_mismatch_produces_high_severity() -> None:
    """GF016: Confirmed digest mismatch produces HIGH severity finding."""
    rr = _make_resolved(
        name="v1.0.0",
        assets=[
            {
                "id": 1,
                "name": "release.whl",
                "label": "",
                "state": "uploaded",
                "size": 1000,
                "content_type": "application/zip",
                "download_count": 0,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "uploader": {"login": "bot"},
                "browser_download_url": "https://github.com/o/r/releases/download/v1/release.whl",
                "url": "https://api.github.com/repos/o/r/releases/assets/1",
                "digest": "sha256:" + "a" * 64,
            }
        ],
    )
    # Manually set digest state on the asset
    asset = rr.release.assets[0]
    object.__setattr__(asset, "digest_state", DigestState.DOWNLOADED_DIGEST_MISMATCH)
    object.__setattr__(asset, "calculated_digest", "b" * 64)

    ctx = _make_context(release_analysis_result=_analysis_result([rr]))
    result = AssetDigestAndAttestationDetector().analyze(ctx)
    assert len(result.findings) >= 1
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 1
    assert "mismatch" in high_findings[0].title.lower()


def test_gf016_missing_digest_binary_asset_produces_info() -> None:
    """GF016: Missing digest on binary asset produces INFO finding."""
    rr = _make_resolved(
        name="v1.0.0",
        assets=[
            {
                "id": 2,
                "name": "app.exe",
                "label": "",
                "state": "uploaded",
                "size": 5000,
                "content_type": "application/octet-stream",
                "download_count": 0,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "uploader": {"login": "bot"},
                "browser_download_url": "https://github.com/o/r/releases/download/v1/app.exe",
                "url": "https://api.github.com/repos/o/r/releases/assets/2",
            }
        ],
    )
    # Asset will have DIGEST_MISSING state by default (no digest in payload)
    ctx = _make_context(release_analysis_result=_analysis_result([rr]))
    result = AssetDigestAndAttestationDetector().analyze(ctx)
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) >= 1


def test_gf016_attestation_repository_mismatch_high_severity() -> None:
    """GF016: Attested repository mismatch produces HIGH severity finding."""
    rr = _make_resolved(name="v1.0.0")
    rr.attestation_state = AttestationState.REPOSITORY_IDENTITY_MISMATCH
    rr.attestation_subject_digest = "a" * 64
    rr.attestation_repository = "https://github.com/attacker/repo"

    ctx = _make_context(release_analysis_result=_analysis_result([rr]))
    result = AssetDigestAndAttestationDetector().analyze(ctx)
    mismatch_findings = [f for f in result.findings if "mismatch" in f.title.lower()]
    assert len(mismatch_findings) >= 1
    assert mismatch_findings[0].severity == Severity.HIGH
    # Must not claim cryptographic verification was performed
    assert not mismatch_findings[0].evidence.data.get("cryptographic_verification_performed")


def test_gf016_matching_attestation_no_finding() -> None:
    """GF016: Matching attestation (non-mismatch state) produces no mismatch finding."""
    rr = _make_resolved(name="v1.0.0")
    rr.attestation_state = AttestationState.MATCHING_ATTESTATION_FOUND

    ctx = _make_context(release_analysis_result=_analysis_result([rr]))
    result = AssetDigestAndAttestationDetector().analyze(ctx)
    mismatch_findings = [
        finding
        for finding in result.findings
        if "repository identity mismatch" in finding.title.lower()
    ]
    assert len(mismatch_findings) == 0


def test_gf016_no_releases_skipped() -> None:
    """GF016: Skipped when no release analysis results."""
    ctx = _make_context()
    result = AssetDigestAndAttestationDetector().analyze(ctx)
    assert result.skipped


# ---------------------------------------------------------------------------
# Determinism and ordering
# ---------------------------------------------------------------------------


def test_release_analysis_result_deterministic_ordering() -> None:
    """Test release analysis output is sorted deterministically by publication date."""
    newer = datetime(2026, 6, 1, tzinfo=UTC)
    older = datetime(2026, 1, 1, tzinfo=UTC)

    rr_newer = _make_resolved(release_id=2, name="v2.0.0", published_at=newer)
    rr_older = _make_resolved(release_id=1, name="v1.0.0", published_at=older)

    from gitforensics.release_analysis import compute_inter_release_diff

    commits = [
        make_synthetic_commit(commit_hash="aaa" + "0" * 37, parents=[]),
    ]
    history = ExtractedHistory(
        repository_path="/s",
        git_dir=".git",
        is_bare=False,
        head_commit="aaa" + "0" * 37,
        commits=commits,
    )

    # Run twice with different input order
    sorted_1 = compute_inter_release_diff([rr_newer, rr_older], history)
    sorted_2 = compute_inter_release_diff([rr_older, rr_newer], history)

    assert [r.release.name for r in sorted_1] == [r.release.name for r in sorted_2]


# ---------------------------------------------------------------------------
# Local analysis unaffected
# ---------------------------------------------------------------------------


def test_local_analysis_unaffected_by_release_failure() -> None:
    """Test that local detector findings are intact when release analysis fails."""
    import tempfile
    from pathlib import Path

    from gitforensics.engine import run_analysis
    from gitforensics.git import parse_repository_input
    from tests.helpers.git_fixtures import add_commit, create_dummy_repo

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        create_dummy_repo(tmp_path)
        add_commit(tmp_path, message="Initial commit")

        repo_input = parse_repository_input(str(tmp_path))
        # Run analysis with offline=True (no release fetching)
        report, context = run_analysis(repo_input, offline=True)

        # Local analysis should still work
        assert report.total_commits >= 1
        assert report.schema_version == "1.0.0"
        # Release analysis should be None in offline mode
        assert report.release_analysis is None
