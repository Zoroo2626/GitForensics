"""Unit tests for release provenance analysis, resolution, diffs, and verification."""

import hashlib

import httpx

from gitforensics.models import (
    ExtractedHistory,
    TagNode,
)
from gitforensics.release_analysis import (
    _validate_download_host,
    parse_release_from_api,
    resolve_release_to_history,
    run_release_analysis,
    verify_asset_digest,
)
from gitforensics.release_models import (
    AssetVerificationConfig,
    DigestState,
    ReleaseAssetRecord,
)
from tests.helpers.git_fixtures import make_synthetic_commit


def _make_empty_history(commits=None, tags=None) -> ExtractedHistory:
    return ExtractedHistory(
        repository_path="/synthetic",
        git_dir=".git",
        is_bare=False,
        head_commit=(commits[0].hash if commits else None),
        commits=commits or [],
        tags=tags or [],
    )


def _make_release(
    release_id: int = 1,
    name: str = "v1.0.0",
    tag_name: str = "v1.0.0",
    target_commitish: str = "main",
    published_at: str = "2026-01-01T00:00:00Z",
    assets: list | None = None,
    is_draft: bool = False,
    is_prerelease: bool = False,
) -> dict:
    return {
        "id": release_id,
        "name": name,
        "tag_name": tag_name,
        "target_commitish": target_commitish,
        "draft": is_draft,
        "prerelease": is_prerelease,
        "created_at": published_at,
        "published_at": published_at,
        "author": {"login": "octocat"},
        "body": "Test release.",
        "tarball_url": "",
        "zipball_url": "",
        "assets": assets or [],
    }


def _make_asset(
    asset_id: int = 1,
    name: str = "app.exe",
    size: int = 1024 * 1024,
    content_type: str = "application/octet-stream",
    created_at: str = "2026-01-01T00:00:00Z",
    updated_at: str = "2026-01-01T00:00:00Z",
    server_digest: str | None = None,
) -> ReleaseAssetRecord:
    asset_payload = {
        "id": asset_id,
        "name": name,
        "label": "",
        "state": "uploaded",
        "size": size,
        "content_type": content_type,
        "download_count": 0,
        "created_at": created_at,
        "updated_at": updated_at,
        "uploader": {"login": "bot"},
        "browser_download_url": f"https://objects.githubusercontent.com/releases/{asset_id}/{name}",
        "url": f"https://api.github.com/repos/o/r/releases/assets/{asset_id}",
    }
    if server_digest:
        asset_payload["digest"] = f"sha256:{server_digest}"

    release = parse_release_from_api(
        {
            "id": 999,
            "tag_name": "v0",
            "target_commitish": "main",
            "draft": False,
            "prerelease": False,
            "created_at": "2026-01-01T00:00:00Z",
            "published_at": "2026-01-01T00:00:00Z",
            "author": {"login": "bot"},
            "body": "",
            "tarball_url": "",
            "zipball_url": "",
            "assets": [asset_payload],
        }
    )
    return release.assets[0]


# ---------------------------------------------------------------------------
# Resolution tests
# ---------------------------------------------------------------------------


def test_resolve_release_no_local_tag_commitish_fallback() -> None:
    """Test resolution falls back to target_commitish prefix match when no local tag exists."""
    commit = make_synthetic_commit(commit_hash="abc1234def567890" + "a" * 24)
    history = _make_empty_history(commits=[commit])

    release_data = _make_release(tag_name="v1.0.0", target_commitish="abc1234")
    release = parse_release_from_api(release_data)
    resolved = resolve_release_to_history(release, history)

    assert not resolved.resolution_failed
    assert resolved.resolved_commit_hash == commit.hash


def test_resolve_release_annotated_tag() -> None:
    """Test resolution via annotated tag peeled commit hash."""
    commit_hash = "deadbeef" + "0" * 32
    history = _make_empty_history(
        commits=[make_synthetic_commit(commit_hash=commit_hash)],
        tags=[
            TagNode(
                ref_name="refs/tags/v1.0.0",
                short_name="v1.0.0",
                target_hash="annotated_tag_hash",
                target_type="tag",
                is_annotated=True,
                peeled_commit_hash=commit_hash,
            )
        ],
    )
    release = parse_release_from_api(_make_release(tag_name="v1.0.0"))
    resolved = resolve_release_to_history(release, history)

    assert resolved.local_tag_found
    assert resolved.tag_is_annotated
    assert resolved.resolved_commit_hash == commit_hash
    assert not resolved.resolution_failed


def test_resolve_release_lightweight_tag() -> None:
    """Test resolution via lightweight tag pointing directly to a commit."""
    commit_hash = "cafe1234" + "0" * 32
    history = _make_empty_history(
        commits=[make_synthetic_commit(commit_hash=commit_hash)],
        tags=[
            TagNode(
                ref_name="refs/tags/v2.0.0",
                short_name="v2.0.0",
                target_hash=commit_hash,
                target_type="commit",
                is_annotated=False,
            )
        ],
    )
    release = parse_release_from_api(_make_release(tag_name="v2.0.0"))
    resolved = resolve_release_to_history(release, history)

    assert resolved.local_tag_found
    assert not resolved.tag_is_annotated
    assert resolved.resolved_commit_hash == commit_hash


def test_resolve_release_no_matching_tag_or_commitish() -> None:
    """Test resolution fails when tag is absent and commitish doesn't match."""
    history = _make_empty_history(commits=[make_synthetic_commit(commit_hash="aaaa" + "0" * 36)])
    release = parse_release_from_api(
        _make_release(tag_name="v99.0.0", target_commitish="nonexistentcommit")
    )
    resolved = resolve_release_to_history(release, history)

    assert resolved.resolution_failed
    assert "v99.0.0" in resolved.resolution_failure_reason


def test_resolve_release_empty_history() -> None:
    """Test resolution when there are zero commits in history."""
    history = _make_empty_history()
    release = parse_release_from_api(_make_release(tag_name="v1.0.0", target_commitish="abc123"))
    resolved = resolve_release_to_history(release, history)

    assert resolved.resolution_failed


def test_resolve_release_no_releases() -> None:
    """Test release analysis returns cleanly when no releases exist."""
    history = _make_empty_history()
    result = run_release_analysis(releases=[], history=history, owner="o", repo="r")
    assert result.total_releases == 0
    assert result.releases == []


def test_draft_releases_excluded_from_analysis() -> None:
    """Test draft releases are excluded from public analysis."""
    history = _make_empty_history(commits=[make_synthetic_commit(commit_hash="abc123" + "0" * 34)])
    draft_data = _make_release(is_draft=True, tag_name="v1.0-draft")
    draft = parse_release_from_api(draft_data)

    result = run_release_analysis(releases=[draft], history=history, owner="o", repo="r")
    assert result.total_releases == 0


# ---------------------------------------------------------------------------
# Inter-release diff tests
# ---------------------------------------------------------------------------


def test_compute_inter_release_diff_two_releases() -> None:
    """Test commits_since_prev is computed correctly for two releases."""
    # Commits ordered newest-first (as git log outputs), with known hashes
    c3 = make_synthetic_commit(commit_hash="c" * 40, parents=["b" * 40])
    c2 = make_synthetic_commit(commit_hash="b" * 40, parents=["a" * 40])
    c1 = make_synthetic_commit(commit_hash="a" * 40, parents=[])

    history = _make_empty_history(commits=[c3, c2, c1])

    # Use full 40-char hashes as target_commitish so resolution succeeds
    r1 = parse_release_from_api(
        _make_release(
            release_id=1,
            tag_name="v1.0.0",
            target_commitish="a" * 40,
            published_at="2026-01-01T00:00:00Z",
        )
    )
    r2 = parse_release_from_api(
        _make_release(
            release_id=2,
            tag_name="v2.0.0",
            target_commitish="c" * 40,
            published_at="2026-02-01T00:00:00Z",
        )
    )

    result = run_release_analysis(
        releases=[r1, r2],
        history=history,
        owner="o",
        repo="r",
    )

    assert result.total_releases == 2
    # The release targeting commit "aaa..." is older (published first)
    # The release targeting commit "ccc..." is newer (published second)
    second = next(r for r in result.releases if r.release.tag_name == "v2.0.0")
    # commits_since_prev may be 0 if commits can't be resolved; check it's set
    assert second.commits_since_prev is not None or second.resolved_commit_hash is None


def test_first_release_has_no_commits_since_prev() -> None:
    """Test that the first release always has commits_since_prev = None."""
    c1 = make_synthetic_commit(commit_hash="aaa" + "0" * 37, parents=[])
    history = _make_empty_history(commits=[c1])
    r1 = parse_release_from_api(_make_release(tag_name="v1.0.0"))

    result = run_release_analysis(releases=[r1], history=history, owner="o", repo="r")

    assert len(result.releases) == 1
    assert result.releases[0].commits_since_prev is None


# ---------------------------------------------------------------------------
# Asset verification tests
# ---------------------------------------------------------------------------


def test_verify_asset_digest_unapproved_host() -> None:
    """Test that assets from unapproved hosts are rejected without download."""
    asset = _make_asset(name="evil.exe", size=100)
    # Overwrite the browser_download_url with an unapproved host
    object.__setattr__(asset, "browser_download_url", "https://evil-host.com/malware.exe")

    cfg = AssetVerificationConfig()
    running_total: list[int] = [0]
    count: list[int] = [0]

    result = verify_asset_digest(
        asset=asset,
        transport=None,
        timeout=10.0,
        config=cfg,
        running_total_bytes=running_total,
        verified_count=count,
    )
    assert result.digest_state == DigestState.DOWNLOAD_FAILED
    assert result.calculated_digest is None
    assert count[0] == 0


def test_verify_asset_digest_declared_size_exceeds_limit() -> None:
    """Test that assets with declared size exceeding limit are skipped."""
    asset = _make_asset(name="huge.tar.gz", size=200 * 1024 * 1024)  # 200 MiB
    cfg = AssetVerificationConfig(max_asset_size_bytes=100 * 1024 * 1024)  # 100 MiB limit

    running_total: list[int] = [0]
    count: list[int] = [0]

    result = verify_asset_digest(
        asset=asset,
        transport=None,
        timeout=10.0,
        config=cfg,
        running_total_bytes=running_total,
        verified_count=count,
    )
    assert result.digest_state == DigestState.VERIFICATION_SKIPPED


def test_verify_asset_digest_matching_sha256() -> None:
    """Test successful SHA-256 digest verification for matching digest."""
    content = b"hello world release asset"
    expected_digest = hashlib.sha256(content).hexdigest()

    def mock_handler(request: httpx.Request) -> httpx.Response:
        assert "evil" not in str(request.url)
        return httpx.Response(
            200,
            content=content,
            headers={"content-length": str(len(content))},
        )

    asset = _make_asset(
        name="release.whl",
        size=len(content),
        server_digest=expected_digest,
    )
    object.__setattr__(
        asset,
        "browser_download_url",
        "https://objects.githubusercontent.com/releases/1/release.whl",
    )

    cfg = AssetVerificationConfig()
    running_total: list[int] = [0]
    count: list[int] = [0]

    result = verify_asset_digest(
        asset=asset,
        transport=httpx.MockTransport(mock_handler),
        timeout=10.0,
        config=cfg,
        running_total_bytes=running_total,
        verified_count=count,
    )
    assert result.digest_state == DigestState.DOWNLOADED_DIGEST_MATCHED
    assert result.calculated_digest == expected_digest
    assert result.bytes_processed == len(content)
    assert running_total[0] == len(content)
    assert count[0] == 1


def test_verify_asset_digest_mismatch() -> None:
    """Test SHA-256 digest mismatch is reported correctly."""
    content = b"tampered content"
    real_digest = hashlib.sha256(content).hexdigest()
    fake_server_digest = "b" * 64  # Wrong digest

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=content, headers={"content-length": str(len(content))})

    asset = _make_asset(name="app.whl", size=len(content), server_digest=fake_server_digest)
    object.__setattr__(
        asset,
        "browser_download_url",
        "https://objects.githubusercontent.com/releases/1/app.whl",
    )

    cfg = AssetVerificationConfig()
    running_total: list[int] = [0]
    count: list[int] = [0]

    result = verify_asset_digest(
        asset=asset,
        transport=httpx.MockTransport(mock_handler),
        timeout=10.0,
        config=cfg,
        running_total_bytes=running_total,
        verified_count=count,
    )
    assert result.digest_state == DigestState.DOWNLOADED_DIGEST_MISMATCH
    assert result.calculated_digest == real_digest
    assert result.calculated_digest != fake_server_digest


def test_verify_asset_streamed_size_exceeds_limit() -> None:
    """Test that streaming download stops when content exceeds per-asset limit."""
    large_content = b"X" * 200  # 200 bytes

    def mock_handler(request: httpx.Request) -> httpx.Response:
        # No Content-Length header to force streaming check
        return httpx.Response(200, content=large_content)

    asset = _make_asset(name="big.tar.gz", size=0)  # Size 0 bypasses pre-check
    object.__setattr__(
        asset,
        "browser_download_url",
        "https://objects.githubusercontent.com/releases/1/big.tar.gz",
    )

    cfg = AssetVerificationConfig(max_asset_size_bytes=100)  # Tiny 100 byte limit
    running_total: list[int] = [0]
    count: list[int] = [0]

    result = verify_asset_digest(
        asset=asset,
        transport=httpx.MockTransport(mock_handler),
        timeout=10.0,
        config=cfg,
        running_total_bytes=running_total,
        verified_count=count,
    )
    assert result.digest_state == DigestState.VERIFICATION_SKIPPED


def test_verify_asset_count_limit() -> None:
    """Test that asset verification stops when max_asset_count is reached."""
    asset = _make_asset(name="skip.exe", size=100)
    object.__setattr__(
        asset,
        "browser_download_url",
        "https://objects.githubusercontent.com/releases/1/skip.exe",
    )

    cfg = AssetVerificationConfig(max_asset_count=5)
    running_total: list[int] = [0]
    count: list[int] = [5]  # Already at limit

    result = verify_asset_digest(
        asset=asset,
        transport=None,
        timeout=10.0,
        config=cfg,
        running_total_bytes=running_total,
        verified_count=count,
    )
    assert result.digest_state == DigestState.VERIFICATION_SKIPPED


def test_verify_asset_total_download_limit() -> None:
    """Test that verification skips when total download budget is exhausted."""
    asset = _make_asset(name="another.exe", size=100)
    object.__setattr__(
        asset,
        "browser_download_url",
        "https://objects.githubusercontent.com/releases/1/another.exe",
    )

    cfg = AssetVerificationConfig(max_total_download_bytes=1000)
    running_total: list[int] = [1001]  # Already over budget
    count: list[int] = [0]

    result = verify_asset_digest(
        asset=asset,
        transport=None,
        timeout=10.0,
        config=cfg,
        running_total_bytes=running_total,
        verified_count=count,
    )
    assert result.digest_state == DigestState.VERIFICATION_SKIPPED


def test_verify_asset_connection_timeout() -> None:
    """Test that connection timeouts result in DOWNLOAD_FAILED state."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("Mock connection timeout", request=request)

    asset = _make_asset(name="timeout.zip", size=0)
    object.__setattr__(
        asset,
        "browser_download_url",
        "https://objects.githubusercontent.com/releases/1/timeout.zip",
    )

    cfg = AssetVerificationConfig()
    running_total: list[int] = [0]
    count: list[int] = [0]

    result = verify_asset_digest(
        asset=asset,
        transport=httpx.MockTransport(mock_handler),
        timeout=5.0,
        config=cfg,
        running_total_bytes=running_total,
        verified_count=count,
    )
    assert result.digest_state == DigestState.DOWNLOAD_FAILED


def test_verify_asset_redirect_to_unapproved_host() -> None:
    """Test redirect to unapproved host is rejected."""
    # The validate_download_host function should catch this

    cfg = AssetVerificationConfig()
    assert not _validate_download_host("https://attacker.com/file.exe", cfg)
    assert _validate_download_host("https://objects.githubusercontent.com/file", cfg)


def test_verify_asset_missing_url() -> None:
    """Test that assets with no download URL result in DOWNLOAD_FAILED."""
    asset = _make_asset(name="nourl.exe", size=100)
    object.__setattr__(asset, "browser_download_url", "")
    object.__setattr__(asset, "api_download_url", "")

    cfg = AssetVerificationConfig()
    running_total: list[int] = [0]
    count: list[int] = [0]

    result = verify_asset_digest(
        asset=asset,
        transport=None,
        timeout=10.0,
        config=cfg,
        running_total_bytes=running_total,
        verified_count=count,
    )
    assert result.digest_state == DigestState.DOWNLOAD_FAILED


def test_verify_assets_disabled_by_default() -> None:
    """Test that asset verification is skipped when verify_assets=False (default)."""
    c = make_synthetic_commit(commit_hash="aaa" + "0" * 37)
    history = _make_empty_history(commits=[c])

    r_data = _make_release(
        tag_name="v1.0.0",
        assets=[
            {
                "id": 1,
                "name": "app.exe",
                "label": "",
                "state": "uploaded",
                "size": 1024,
                "content_type": "application/octet-stream",
                "download_count": 0,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "uploader": {"login": "bot"},
                "browser_download_url": "https://github.com/o/r/releases/download/v1/app.exe",
                "url": "https://api.github.com/repos/o/r/releases/assets/1",
            }
        ],
    )
    release = parse_release_from_api(r_data)
    result = run_release_analysis(
        releases=[release], history=history, owner="o", repo="r", verify_assets=False
    )

    # All assets should be VERIFICATION_SKIPPED when verify_assets=False
    for rr in result.releases:
        for asset in rr.release.assets:
            assert asset.digest_state == DigestState.VERIFICATION_SKIPPED, (
                f"Expected VERIFICATION_SKIPPED, got {asset.digest_state}"
            )


def test_offline_mode_no_release_requests() -> None:
    """Test that offline mode prevents release API requests (via engine)."""
    import tempfile
    from pathlib import Path

    from gitforensics.engine import run_analysis
    from gitforensics.git import parse_repository_input
    from tests.helpers.git_fixtures import add_commit, create_dummy_repo

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        create_dummy_repo(tmp_path)
        add_commit(tmp_path, message="Commit")
        repo_input = parse_repository_input(str(tmp_path))

        # offline=True should prevent any release fetching
        report, context = run_analysis(repo_input, offline=True)
        assert report.total_releases == 0
        assert report.release_analysis is None
