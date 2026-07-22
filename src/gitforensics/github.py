"""Bounded GitHub REST API client for untrusted response data."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

import httpx

from gitforensics import __version__
from gitforensics.compat import parse_iso_datetime
from gitforensics.errors import (
    GitHubAPIError,
    GitHubAuthError,
    GitHubNetworkError,
    GitHubNotFoundError,
    GitHubRateLimitError,
    GitHubResponseLimitError,
    MalformedGitHubResponseError,
)
from gitforensics.models import GitHubMetadata, WorkflowFile
from gitforensics.security import SecurityLimits, sanitize_text

logger = logging.getLogger(__name__)

LINK_HEADER_PATTERN = re.compile(r'<([^>]+)>;\s*rel="([^"]+)"')
_REPOSITORY_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_WORKFLOW_NAME = re.compile(r"^[^/\\\x00]{1,255}\.(?:yml|yaml)$", re.IGNORECASE)


class _BorrowedTransport(httpx.BaseTransport):
    """Delegate requests without letting an ephemeral client close the shared transport."""

    def __init__(self, transport: httpx.BaseTransport) -> None:
        self._transport = transport

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self._transport.handle_request(request)

    def close(self) -> None:
        """Leave transport ownership with the main API client."""


@dataclass(frozen=True)
class GitHubCollectionResult:
    """A bounded API collection that preserves valid items when truncation occurs."""

    items: tuple[dict[str, Any], ...]
    truncated: bool = False
    truncation_reason: str = ""


@dataclass(frozen=True)
class GitHubWorkflowResult:
    """Bounded workflow collection plus deterministic incomplete-analysis reasons."""

    workflows: tuple[WorkflowFile, ...]
    incomplete_reasons: tuple[str, ...] = ()


class GitHubClient:
    """HTTP client with token-safe errors, bounded bodies, and strict redirect policy."""

    def __init__(
        self,
        token: str | None = None,
        base_url: str = "https://api.github.com",
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
        max_retries: int = 2,
        limits: SecurityLimits | None = None,
        allowed_api_hosts: frozenset[str] | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("GitHub timeout must be positive.")
        if max_retries < 0 or max_retries > 10:
            raise ValueError("GitHub retry count must be between 0 and 10.")
        parsed = urlsplit(base_url.rstrip("/"))
        approved_hosts = allowed_api_hosts or frozenset({"api.github.com"})
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.hostname.lower() not in approved_hosts
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("GitHub API URL must be an approved credential-free HTTPS origin.")

        self._token = token.strip() if token and token.strip() else None
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self._transport = transport
        self.limits = limits or SecurityLimits()
        self.limits.validate()
        self._base_origin = (parsed.scheme, parsed.hostname.lower(), parsed.port)
        self._client = httpx.Client(
            timeout=httpx.Timeout(self.timeout, connect=self.timeout),
            transport=self._transport,
            follow_redirects=False,
        )

    def close(self) -> None:
        """Close connections owned by this client instance."""
        self._client.close()

    def __enter__(self) -> GitHubClient:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()

    def __repr__(self) -> str:
        auth_str = "authenticated" if self._token else "unauthenticated"
        return f"<GitHubClient base_url='{self.base_url}' status='{auth_str}'>"

    def is_authenticated(self) -> bool:
        return self._token is not None

    def _get_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "Accept-Encoding": "identity",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": f"GitForensics/{__version__}",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _same_origin_url(self, endpoint: str) -> str:
        url = urljoin(self.base_url + "/", endpoint)
        parsed = urlsplit(url)
        origin = (parsed.scheme, (parsed.hostname or "").lower(), parsed.port)
        if origin != self._base_origin or parsed.username or parsed.password:
            raise GitHubAPIError("GitHub API pagination attempted to leave the approved origin.")
        return url

    def _request(
        self, method: str, endpoint: str, params: dict[str, Any] | None = None
    ) -> httpx.Response:
        """Make a bounded request; API redirects are rejected to protect credentials."""
        url = self._same_origin_url(endpoint)
        attempts = 0
        while True:
            attempts += 1
            try:
                with self._client.stream(
                    method,
                    url,
                    headers=self._get_headers(),
                    params=params,
                ) as streamed:
                    if streamed.is_redirect:
                        raise GitHubAPIError("GitHub API redirect was rejected.")
                    declared = streamed.headers.get("content-length")
                    too_large = (
                        declared
                        and declared.isdigit()
                        and int(declared) > self.limits.max_api_response_bytes
                    )
                    if too_large:
                        raise GitHubResponseLimitError(
                            "GitHub API response exceeded the configured byte limit."
                        )
                    body = bytearray()
                    for chunk in streamed.iter_bytes(64 * 1024):
                        body.extend(chunk)
                        if len(body) > self.limits.max_api_response_bytes:
                            raise GitHubResponseLimitError(
                                "GitHub API response exceeded the configured byte limit."
                            )
                    response = httpx.Response(
                        streamed.status_code,
                        headers=streamed.headers,
                        content=bytes(body),
                        request=streamed.request,
                    )

                if response.status_code == 429 or (
                    response.status_code == 403
                    and response.headers.get("X-RateLimit-Remaining") == "0"
                ):
                    reset_str = response.headers.get("X-RateLimit-Reset")
                    reset_time = int(reset_str) if reset_str and reset_str.isdigit() else None
                    raise GitHubRateLimitError(
                        "GitHub API rate limit exceeded.",
                        reset_timestamp=reset_time,
                        status_code=response.status_code,
                    )
                if response.status_code == 404:
                    raise GitHubNotFoundError("Resource not found on GitHub API.")
                if response.status_code in (401, 403):
                    raise GitHubAuthError(
                        f"GitHub API authentication/permission error ({response.status_code}).",
                        status_code=response.status_code,
                    )
                if response.status_code in {500, 502, 503, 504} and attempts <= self.max_retries:
                    continue
                if response.is_error:
                    raise GitHubAPIError(
                        f"GitHub API error HTTP {response.status_code}",
                        status_code=response.status_code,
                    )
                return response
            except GitHubAPIError:
                raise
            except (httpx.TimeoutException, httpx.NetworkError, httpx.ProtocolError) as err:
                if attempts <= self.max_retries:
                    continue
                safe_error = sanitize_text(
                    str(err), max_chars=500, secrets=(self._token,), minimize_emails=False
                )
                raise GitHubNetworkError(f"GitHub API network failure: {safe_error}") from err

    @staticmethod
    def _json(response: httpx.Response, expected: type[Any]) -> Any:
        try:
            data = response.json()
        except (ValueError, UnicodeError) as err:
            raise MalformedGitHubResponseError("GitHub API returned malformed JSON.") from err
        if not isinstance(data, expected):
            raise MalformedGitHubResponseError("GitHub API returned an unexpected JSON schema.")
        return data

    @staticmethod
    def _component(value: str, label: str) -> str:
        if not _REPOSITORY_COMPONENT.fullmatch(value):
            raise ValueError(f"Invalid GitHub {label}.")
        return quote(value, safe="")

    def get_repository_metadata(self, owner: str, repo: str) -> GitHubMetadata:
        safe_owner = self._component(owner, "owner")
        safe_repo = self._component(repo, "repository")
        data = self._json(self._request("GET", f"repos/{safe_owner}/{safe_repo}"), dict)

        def text(key: str, default: str = "") -> str:
            value = data.get(key, default)
            return sanitize_text(str(value), max_chars=1_024) if isinstance(value, str) else default

        def integer(key: str) -> int:
            value = data.get(key, 0)
            valid = isinstance(value, int) and not isinstance(value, bool) and value >= 0
            return value if valid else 0

        owner_value = data.get("owner")
        owner_data: dict[str, Any] = owner_value if isinstance(owner_value, dict) else {}
        parent_value = data.get("parent")
        parent: dict[str, Any] = parent_value if isinstance(parent_value, dict) else {}
        parent_owner_value = parent.get("owner")
        parent_owner: dict[str, Any] = (
            parent_owner_value if isinstance(parent_owner_value, dict) else {}
        )
        license_value = data.get("license")
        license_data: dict[str, Any] = license_value if isinstance(license_value, dict) else {}
        topics = data.get("topics") if isinstance(data.get("topics"), list) else []
        safe_topics = [
            sanitize_text(item, max_chars=100) for item in topics[:100] if isinstance(item, str)
        ]

        return GitHubMetadata(
            owner=sanitize_text(str(owner_data.get("login", owner)), max_chars=100),
            name=text("name", repo),
            repo_id=integer("id"),
            created_at=parse_iso_datetime(data.get("created_at")),
            updated_at=parse_iso_datetime(data.get("updated_at")),
            pushed_at=parse_iso_datetime(data.get("pushed_at")),
            default_branch=text("default_branch", "main"),
            visibility=text("visibility", "public"),
            archived=data.get("archived") is True,
            disabled=data.get("disabled") is True,
            is_fork=data.get("fork") is True,
            parent_owner=sanitize_text(str(parent_owner.get("login")), max_chars=100)
            if parent_owner.get("login")
            else None,
            parent_name=sanitize_text(str(parent.get("name")), max_chars=100)
            if parent.get("name")
            else None,
            size=integer("size"),
            open_issues_count=integer("open_issues_count"),
            stargazers_count=integer("stargazers_count"),
            forks_count=integer("forks_count"),
            watchers_count=integer("subscribers_count") or integer("watchers_count"),
            language=text("language") or None,
            license=sanitize_text(str(license_data.get("spdx_id")), max_chars=100)
            if license_data.get("spdx_id")
            else None,
            topics=safe_topics,
        )

    def get_releases(self, owner: str, repo: str, per_page: int = 30) -> list[dict[str, Any]]:
        """Return releases, raising if the bounded result was truncated."""
        result = self.get_releases_bounded(owner, repo, per_page=per_page)
        if result.truncated:
            raise GitHubResponseLimitError(result.truncation_reason)
        return list(result.items)

    def get_releases_bounded(
        self, owner: str, repo: str, per_page: int = 30
    ) -> GitHubCollectionResult:
        """Fetch releases while retaining valid bounded items on a hard limit."""
        safe_owner = self._component(owner, "owner")
        safe_repo = self._component(repo, "repository")
        endpoint = f"repos/{safe_owner}/{safe_repo}/releases"
        params: dict[str, Any] = {"per_page": min(max(per_page, 1), 100)}
        releases: list[dict[str, Any]] = []
        requested_urls: set[str] = set()

        for _page in range(1, self.limits.max_api_pages + 1):
            request_url = self._same_origin_url(endpoint)
            if request_url in requested_urls:
                return GitHubCollectionResult(
                    tuple(releases),
                    True,
                    "GitHub API pagination repeated a page URL.",
                )
            requested_urls.add(request_url)
            remaining = self.limits.max_releases - len(releases)
            params["per_page"] = min(params.get("per_page", 30), remaining + 1, 100)
            response = self._request("GET", endpoint, params=params)
            page_data = self._json(response, list)
            for item in page_data:
                if isinstance(item, dict):
                    if len(releases) >= self.limits.max_releases:
                        return GitHubCollectionResult(
                            tuple(releases),
                            True,
                            "GitHub release count exceeded the configured limit.",
                        )
                    releases.append(item)
            next_url = next(
                (
                    match.group(1)
                    for match in LINK_HEADER_PATTERN.finditer(response.headers.get("Link", ""))
                    if match.group(2) == "next"
                ),
                None,
            )
            if not next_url:
                return GitHubCollectionResult(tuple(releases))
            if len(releases) >= self.limits.max_releases:
                return GitHubCollectionResult(
                    tuple(releases),
                    True,
                    "GitHub release count reached the configured limit before pagination ended.",
                )
            endpoint = self._same_origin_url(next_url)
            params = {}
        return GitHubCollectionResult(
            tuple(releases),
            True,
            "GitHub API pagination exceeded the configured page limit.",
        )

    def _download_workflow(self, url: str) -> str | None:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or (parsed.hostname or "").lower() not in {"raw.githubusercontent.com", "github.com"}
            or parsed.username
            or parsed.password
        ):
            return None
        try:
            workflow_transport = (
                _BorrowedTransport(self._transport) if self._transport is not None else None
            )
            with httpx.Client(
                timeout=httpx.Timeout(self.timeout, connect=self.timeout),
                transport=workflow_transport,
                follow_redirects=False,
            ) as workflow_client:
                with workflow_client.stream(
                    "GET", url, headers={"Accept-Encoding": "identity"}
                ) as response:
                    if response.status_code != 200 or response.is_redirect:
                        return None
                    raw = bytearray()
                    for chunk in response.iter_bytes(64 * 1024):
                        raw.extend(chunk)
                        if len(raw) > self.limits.max_workflow_file_bytes:
                            return None
            return bytes(raw).decode("utf-8", errors="replace")
        except (httpx.HTTPError, UnicodeError):
            return None

    def get_workflow_files(self, owner: str, repo: str) -> list[WorkflowFile]:
        """Return safely downloaded workflow files for compatibility callers."""
        return list(self.get_workflow_files_bounded(owner, repo).workflows)

    def get_workflow_files_bounded(self, owner: str, repo: str) -> GitHubWorkflowResult:
        """Return workflows and explicit reasons for any bounded omissions."""
        safe_owner = self._component(owner, "owner")
        safe_repo = self._component(repo, "repository")
        try:
            response = self._request(
                "GET", f"repos/{safe_owner}/{safe_repo}/contents/.github/workflows"
            )
        except GitHubNotFoundError:
            return GitHubWorkflowResult(())
        items = self._json(response, list)
        workflows: list[WorkflowFile] = []
        incomplete_reasons: list[str] = []
        fetched_urls: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            is_workflow = (
                item.get("type") == "file"
                and isinstance(name, str)
                and _WORKFLOW_NAME.fullmatch(name)
            )
            if not is_workflow:
                continue
            assert isinstance(name, str)
            if len(workflows) >= self.limits.max_workflow_files:
                incomplete_reasons.append(
                    "Remote workflow analysis reached the configured file limit."
                )
                break
            size = item.get("size")
            if isinstance(size, int) and size > self.limits.max_workflow_file_bytes:
                incomplete_reasons.append("An oversized remote workflow was omitted from analysis.")
                continue
            download_url = item.get("download_url")
            if not isinstance(download_url, str) or download_url in fetched_urls:
                continue
            fetched_urls.add(download_url)
            content = self._download_workflow(download_url)
            if content is None:
                logger.warning("Workflow file could not be fetched safely: %s", sanitize_text(name))
                incomplete_reasons.append(
                    "A remote workflow could not be fetched within security limits."
                )
                continue
            safe_name = sanitize_text(name, max_chars=255, minimize_emails=False)
            workflows.append(
                WorkflowFile(
                    path=f".github/workflows/{safe_name}",
                    name=safe_name,
                    content=content,
                    lines=content.splitlines(),
                )
            )
        return GitHubWorkflowResult(
            tuple(workflows),
            tuple(sorted(set(incomplete_reasons))),
        )
