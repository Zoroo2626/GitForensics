"""Unit tests for release model parsing and asset classification."""

import pytest

from gitforensics.release_analysis import parse_release_from_api
from gitforensics.release_models import (
    AssetCategory,
    AssetVerificationConfig,
    DigestState,
    classify_asset,
)

# ---------------------------------------------------------------------------
# classify_asset tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,content_type,expected",
    [
        ("setup.exe", "application/octet-stream", AssetCategory.WINDOWS_EXE),
        ("installer.msi", "application/octet-stream", AssetCategory.WINDOWS_EXE),
        ("myapp.dll", "application/octet-stream", AssetCategory.SHARED_LIBRARY),
        ("app.dylib", "application/octet-stream", AssetCategory.SHARED_LIBRARY),
        ("disk.dmg", "application/octet-stream", AssetCategory.DISK_IMAGE),
        ("server.jar", "application/java-archive", AssetCategory.JAVA_ARCHIVE),
        ("tool.whl", "application/octet-stream", AssetCategory.PYTHON_WHEEL),
        ("package-1.0.tar.gz", "application/octet-stream", AssetCategory.PYTHON_SDIST),
        ("mypackage.tgz", "application/octet-stream", AssetCategory.NODE_PACKAGE),
        ("archive.zip", "application/zip", AssetCategory.COMPRESSED_ARCHIVE),
        ("checksums.sha256", "text/plain", AssetCategory.CHECKSUM),
        ("release.asc", "application/pgp-signature", AssetCategory.SIGNATURE),
        ("sbom.spdx", "text/plain", AssetCategory.SBOM),
        ("source.tar.gz", "application/x-tar", AssetCategory.SOURCE_ARCHIVE),
        ("unknown.bin", "application/octet-stream", AssetCategory.UNKNOWN),
    ],
)
def test_classify_asset_categories(name: str, content_type: str, expected: AssetCategory) -> None:
    """Test asset classification returns expected categories."""
    assert classify_asset(name, content_type) == expected


# ---------------------------------------------------------------------------
# parse_release_from_api tests
# ---------------------------------------------------------------------------


def _make_release_payload(**overrides) -> dict:
    """Helper to build a complete release API payload."""
    payload = {
        "id": 12345,
        "name": "v1.0.0",
        "tag_name": "v1.0.0",
        "target_commitish": "main",
        "draft": False,
        "prerelease": False,
        "created_at": "2026-01-01T00:00:00Z",
        "published_at": "2026-01-01T01:00:00Z",
        "author": {"login": "octocat"},
        "body": "Release notes go here.",
        "tarball_url": "https://github.com/owner/repo/tarball/v1.0.0",
        "zipball_url": "https://github.com/owner/repo/zipball/v1.0.0",
        "assets": [],
    }
    payload.update(overrides)
    return payload


def test_parse_release_normal() -> None:
    """Test parsing a normal, complete release response."""
    payload = _make_release_payload(
        assets=[
            {
                "id": 99,
                "name": "app.exe",
                "label": "",
                "state": "uploaded",
                "size": 1024 * 1024,
                "content_type": "application/octet-stream",
                "download_count": 42,
                "created_at": "2026-01-01T01:00:00Z",
                "updated_at": "2026-01-01T01:00:00Z",
                "uploader": {"login": "octocat"},
                "browser_download_url": "https://github.com/owner/repo/releases/download/v1.0.0/app.exe",
                "url": "https://api.github.com/repos/owner/repo/releases/assets/99",
            }
        ]
    )
    release = parse_release_from_api(payload)
    assert release.release_id == 12345
    assert release.name == "v1.0.0"
    assert release.tag_name == "v1.0.0"
    assert not release.is_draft
    assert not release.is_prerelease
    assert release.body_length == len("Release notes go here.")
    assert len(release.assets) == 1
    asset = release.assets[0]
    assert asset.asset_id == 99
    assert asset.name == "app.exe"
    assert asset.category == AssetCategory.WINDOWS_EXE
    assert asset.digest_state == DigestState.DIGEST_MISSING


def test_parse_release_draft_flag() -> None:
    """Test parsing a draft release."""
    release = parse_release_from_api(_make_release_payload(draft=True, published_at=None))
    assert release.is_draft
    assert release.published_at is None


def test_parse_release_prerelease_flag() -> None:
    """Test parsing a pre-release."""
    release = parse_release_from_api(_make_release_payload(prerelease=True))
    assert release.is_prerelease


def test_parse_release_missing_optional_fields() -> None:
    """Test parsing a release with many optional fields absent."""
    minimal = {
        "id": 1,
        "tag_name": "v0.1",
        "target_commitish": "abc123",
        "draft": False,
        "prerelease": False,
        "created_at": "2026-01-01T00:00:00Z",
        "assets": [],
    }
    release = parse_release_from_api(minimal)
    assert release.release_id == 1
    assert release.name == ""
    assert release.published_at is None
    assert release.body_length == 0
    assert release.author_login == ""


def test_parse_release_asset_with_sha256_digest() -> None:
    """Test parsing an asset with a server-supplied SHA-256 digest."""
    digest_hex = "a" * 64
    payload = _make_release_payload(
        assets=[
            {
                "id": 1,
                "name": "release.whl",
                "label": "",
                "state": "uploaded",
                "size": 500,
                "content_type": "application/zip",
                "download_count": 0,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "uploader": {"login": "bot"},
                "browser_download_url": "https://github.com/o/r/releases/download/v1/release.whl",
                "url": "https://api.github.com/repos/o/r/releases/assets/1",
                "digest": f"sha256:{digest_hex}",
            }
        ]
    )
    release = parse_release_from_api(payload)
    asset = release.assets[0]
    assert asset.server_digest == digest_hex
    assert asset.digest_state == DigestState.SERVER_SHA256_AVAILABLE


def test_parse_release_asset_with_malformed_digest() -> None:
    """Test parsing an asset with a malformed digest string."""
    payload = _make_release_payload(
        assets=[
            {
                "id": 2,
                "name": "app.tar.gz",
                "label": "",
                "state": "uploaded",
                "size": 200,
                "content_type": "application/gzip",
                "download_count": 0,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "uploader": {"login": "bot"},
                "browser_download_url": "https://github.com/o/r/releases/download/v1/app.tar.gz",
                "url": "https://api.github.com/repos/o/r/releases/assets/2",
                "digest": "not-a-valid-hex-digest",
            }
        ]
    )
    release = parse_release_from_api(payload)
    asset = release.assets[0]
    assert asset.server_digest is None
    assert asset.digest_state == DigestState.DIGEST_MALFORMED


def test_asset_verification_config_validation() -> None:
    """Test AssetVerificationConfig raises ValueError for invalid settings."""
    with pytest.raises(ValueError, match="max_asset_size_bytes must be positive"):
        AssetVerificationConfig(max_asset_size_bytes=0).validate()

    with pytest.raises(ValueError, match="max_total_download_bytes must be positive"):
        AssetVerificationConfig(max_total_download_bytes=-1).validate()

    with pytest.raises(ValueError, match="max_asset_count must be positive"):
        AssetVerificationConfig(max_asset_count=0).validate()


def test_release_record_to_dict() -> None:
    """Test ReleaseRecord.to_dict produces JSON-safe output."""
    release = parse_release_from_api(_make_release_payload())
    d = release.to_dict()
    assert d["release_id"] == 12345
    assert d["tag_name"] == "v1.0.0"
    assert isinstance(d["assets"], list)
    assert isinstance(d["published_at"], str)
