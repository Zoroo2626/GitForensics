"""Regression tests for the final independent security-audit fixes."""

import base64
import json
import os
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from gitforensics.errors import CLIArgumentError
from gitforensics.git import GitRunner, parse_repository_input
from gitforensics.github import GitHubClient
from gitforensics.release_analysis import lookup_attestation, parse_release_from_api
from gitforensics.release_models import AttestationState, ReleaseAssetRecord
from gitforensics.reporting import _is_pid_running


def _release_asset() -> ReleaseAssetRecord:
    digest = "a" * 64
    release = parse_release_from_api(
        {
            "id": 1,
            "tag_name": "v1",
            "assets": [
                {
                    "id": 2,
                    "name": "artifact.zip",
                    "digest": f"sha256:{digest}",
                    "created_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-01T00:00:00Z",
                }
            ],
        }
    )
    return release.assets[0]


def _attestation_transport(repository_uri: str | None) -> httpx.MockTransport:
    resolved_dependencies = [] if repository_uri is None else [{"uri": repository_uri}]
    predicate = {
        "predicate": {
            "buildDefinition": {
                "resolvedDependencies": resolved_dependencies,
            }
        }
    }
    payload = base64.b64encode(json.dumps(predicate).encode("utf-8")).decode("ascii")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"attestations": [{"bundle": {"dsseEnvelope": {"payload": payload}}}]},
        )

    return httpx.MockTransport(handler)


def test_workflow_download_does_not_reuse_authenticated_client_state() -> None:
    token = "github-token-value"
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.host == "api.github.com":
            assert request.headers["Authorization"] == f"Bearer {token}"
            return httpx.Response(
                200,
                json=[
                    {
                        "type": "file",
                        "name": "audit.yml",
                        "size": 20,
                        "download_url": "https://github.com/o/r/raw/main/audit.yml",
                    }
                ],
                headers={"Set-Cookie": "api_session=sensitive; Domain=github.com; Path=/; Secure"},
            )
        assert request.url.host == "github.com"
        assert "Authorization" not in request.headers
        assert "Cookie" not in request.headers
        return httpx.Response(200, content=b"run: echo safe")

    with GitHubClient(token=token, transport=httpx.MockTransport(handler)) as client:
        workflows = client.get_workflow_files("o", "r")

    assert len(workflows) == 1
    assert len(calls) == 2


def test_git_askpass_is_documented_noninteractive_helper(tmp_path: Path) -> None:
    env = GitRunner._safe_environment(str(tmp_path))

    assert env["GIT_ASKPASS"] == "echo"
    assert env["GIT_TERMINAL_PROMPT"] == "0"


def test_attestation_repository_identity_rejects_prefix_match() -> None:
    state, subject, repository, _workflow = lookup_attestation(
        _release_asset(),
        "owner",
        "repo",
        _attestation_transport("https://github.com/owner/repo-backdoored"),
        1.0,
        None,
        "https://api.github.com",
    )

    assert state == AttestationState.REPOSITORY_IDENTITY_MISMATCH
    assert subject == "a" * 64
    assert repository == "https://github.com/owner/repo-backdoored"


def test_attestation_repository_identity_allows_case_and_trailing_slash() -> None:
    state, subject, repository, _workflow = lookup_attestation(
        _release_asset(),
        "owner",
        "repo",
        _attestation_transport("HTTPS://GITHUB.COM/OWNER/REPO/"),
        1.0,
        None,
        "https://api.github.com",
    )

    assert state == AttestationState.MATCHING_ATTESTATION_FOUND
    assert subject == "a" * 64
    assert repository == "https://github.com/OWNER/REPO/"


def test_attestation_without_repository_identity_is_not_reported_as_matching() -> None:
    state, subject, repository, workflow = lookup_attestation(
        _release_asset(),
        "owner",
        "repo",
        _attestation_transport(None),
        1.0,
        None,
        "https://api.github.com",
    )

    assert state == AttestationState.ATTESTATION_RESPONSE_MALFORMED
    assert subject is None
    assert repository is None
    assert workflow is None


def test_insecure_github_http_url_is_rejected() -> None:
    with pytest.raises(CLIArgumentError, match="Insecure GitHub HTTP"):
        parse_repository_input("http://github.com/owner/repo")


def test_release_asset_signed_query_is_removed_before_report_serialization() -> None:
    secret = "signed-query-secret"
    release = parse_release_from_api(
        {
            "id": 1,
            "tag_name": "v1",
            "assets": [
                {
                    "id": 2,
                    "name": "artifact.zip",
                    "created_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-01T00:00:00Z",
                    "browser_download_url": (
                        "https://github.com/o/r/releases/download/v1/artifact.zip"
                        f"?X-Amz-Signature={secret}"
                    ),
                }
            ],
        }
    )

    asset = release.assets[0]
    assert asset.browser_download_url.endswith("/artifact.zip")
    assert "?" not in asset.to_dict()["browser_download_url"]
    assert secret not in json.dumps(release.to_dict())


def test_ci_installs_project_and_runtime_dependencies() -> None:
    project_root = Path(__file__).parents[2]
    workflow = (project_root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "python -m pip install -e ." in workflow


def test_pid_probe_uses_platform_safe_mechanism() -> None:
    if os.name == "nt":
        with patch(
            "gitforensics.reporting.os.kill", side_effect=AssertionError("unsafe PID probe")
        ):
            assert _is_pid_running(os.getpid())
    else:
        with patch("gitforensics.reporting.os.kill") as posix_probe:
            assert _is_pid_running(os.getpid())
        posix_probe.assert_called_once_with(os.getpid(), 0)
