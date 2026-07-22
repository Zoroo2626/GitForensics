"""Git repository acquisition, validation, and history extraction module."""

import hashlib
import io
import os
import re
import shutil
import subprocess
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from heapq import nsmallest
from pathlib import Path
from typing import Any, BinaryIO

from gitforensics.compat import UTC
from gitforensics.errors import (
    CLIArgumentError,
    GitCloneError,
    GitCommandError,
    GitForensicsError,
    GitOutputLimitError,
    GitTimeoutError,
    InvalidGitRepositoryError,
    RepositoryNotFoundError,
    TemporaryCleanupError,
)
from gitforensics.models import (
    CommitNode,
    ExtractedHistory,
    RepositoryInput,
    RepositoryInputType,
    RepositoryStateMarker,
    SignatureStatus,
    TagNode,
    WorkflowFile,
)
from gitforensics.security import SecurityLimits, sanitize_text

WINDOWS_PATH_PATTERN = re.compile(r"^[a-zA-Z]:[\\/]")
GITHUB_SHORTHAND_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$")
GITHUB_URL_PATTERN = re.compile(
    r"^(https://github\.com/|git@github\.com:)([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(\.git)?$"
)
UNSUPPORTED_SCHEMES = ("ftp://", "file://", "ssh://", "svn://")

_HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{40,64}$")
_SHORTSTAT_FILES_RE = re.compile(r"(\d+) files? changed")
_SHORTSTAT_INSERTIONS_RE = re.compile(r"(\d+) insertions?\(\+\)")
_SHORTSTAT_DELETIONS_RE = re.compile(r"(\d+) deletions?\(-\)")
_ALLOWED_GIT_COMMANDS = frozenset(
    {"clone", "for-each-ref", "log", "rev-parse", "status", "version"}
)


def parse_repository_input(raw_input: str) -> RepositoryInput:
    """Parses, normalizes, and validates a repository input (local path or remote URL)."""
    if not raw_input or not raw_input.strip():
        raise CLIArgumentError("Repository path or URL cannot be empty.")

    raw = raw_input.strip()
    if "\x00" in raw or any(ord(char) < 32 for char in raw):
        raise CLIArgumentError("Repository input contains invalid control characters.")

    # Reject unsupported URL schemes
    for scheme in UNSUPPORTED_SCHEMES:
        if raw.startswith(scheme):
            raise CLIArgumentError(f"Unsupported URL scheme: {scheme}")

    if raw.startswith("http://github.com/"):
        raise CLIArgumentError("Insecure GitHub HTTP URLs are not supported; use HTTPS.")

    # GitHub shorthand (e.g. owner/repo)
    if GITHUB_SHORTHAND_PATTERN.match(raw) and not Path(raw).exists():
        resolved_url = f"https://github.com/{raw}.git"
        return RepositoryInput(
            raw_input=raw,
            input_type=RepositoryInputType.REMOTE,
            resolved_path_or_url=resolved_url,
        )

    # Remote GitHub URL check
    if raw.startswith(("http://", "https://", "git@")):
        match = GITHUB_URL_PATTERN.match(raw)
        if not match:
            raise CLIArgumentError(f"Malformed or unsupported GitHub URL: {raw}")
        owner, repo = match.group(2), match.group(3)
        resolved_url = f"https://github.com/{owner}/{repo}.git"
        return RepositoryInput(
            raw_input=raw,
            input_type=RepositoryInputType.REMOTE,
            resolved_path_or_url=resolved_url,
        )

    # Windows path detection
    if WINDOWS_PATH_PATTERN.match(raw):
        norm_path_str = raw.replace("\\", "/")
        if os.name == "nt":
            path = Path(norm_path_str)
            if not path.exists():
                raise RepositoryNotFoundError(f"Local repository path does not exist: {raw}")
            if not path.is_dir():
                raise CLIArgumentError(f"Specified path is not a directory: {raw}")
        return RepositoryInput(
            raw_input=raw,
            input_type=RepositoryInputType.LOCAL,
            resolved_path_or_url=str(path.resolve()) if os.name == "nt" else norm_path_str,
        )

    # Standard local path validation
    path = Path(raw).expanduser()

    if not path.exists():
        raise RepositoryNotFoundError(f"Local repository path does not exist: {raw}")

    if not path.is_dir():
        raise CLIArgumentError(f"Specified path is not a directory: {raw}")

    return RepositoryInput(
        raw_input=raw,
        input_type=RepositoryInputType.LOCAL,
        resolved_path_or_url=str(path.resolve()),
    )


@dataclass(frozen=True)
class GitCommandResult:
    """Typed result of a Git command subprocess execution."""

    command: list[str]
    stdout: str
    stderr: str
    returncode: int


class GitRunner:
    """Safely executes Git commands via subprocess with strict controls."""

    def __init__(
        self,
        default_timeout: float = 30.0,
        max_stdout_bytes: int = 64 * 1024 * 1024,
        max_stderr_bytes: int = 1 * 1024 * 1024,
    ) -> None:
        if default_timeout <= 0:
            raise ValueError("default_timeout must be positive.")
        if max_stdout_bytes <= 0 or max_stderr_bytes <= 0:
            raise ValueError("Git output limits must be positive.")
        self.default_timeout = default_timeout
        self.max_stdout_bytes = max_stdout_bytes
        self.max_stderr_bytes = max_stderr_bytes

    @staticmethod
    def _safe_environment(home: str) -> dict[str, str]:
        """Build a small environment that strips all caller-controlled Git variables."""
        allowed = {
            "COMSPEC",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "LANG",
            "LC_ALL",
            "NO_PROXY",
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "WINDIR",
        }
        env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
        env.update(
            {
                "GIT_ASKPASS": "echo",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_EDITOR": "true",
                "GIT_FLUSH": "1",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_PAGER": "cat",
                "GIT_SEQUENCE_EDITOR": "true",
                "GIT_TERMINAL_PROMPT": "0",
                "HOME": home,
                "LANG": "C",
                "LC_ALL": "C",
                "PAGER": "cat",
                "XDG_CONFIG_HOME": home,
            }
        )
        return env

    @staticmethod
    def _drain_stream(
        stream: BinaryIO,
        destination: bytearray,
        limit: int,
        overflow: threading.Event,
        process: subprocess.Popen[bytes],
    ) -> None:
        """Drain one pipe while retaining at most ``limit`` bytes."""
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            remaining = limit + 1 - len(destination)
            if remaining > 0:
                destination.extend(chunk[:remaining])
            if len(destination) > limit:
                overflow.set()
                try:
                    process.kill()
                except OSError:
                    pass
                break

    def run(
        self,
        args: list[str],
        cwd: Path | str | None = None,
        timeout: float | None = None,
        check: bool = True,
    ) -> GitCommandResult:
        """Executes a Git plumbing command without shell=True."""
        if not isinstance(args, list):
            raise TypeError("Git command arguments must be passed as a list.")
        if not args or any(not isinstance(arg, str) for arg in args):
            raise TypeError("Git command arguments must be non-empty strings.")
        if any("\x00" in arg for arg in args):
            raise ValueError("Git command arguments cannot contain NUL bytes.")
        if args[0] not in _ALLOWED_GIT_COMMANDS:
            raise ValueError(f"Git command is not approved for read-only analysis: {args[0]!r}")

        full_cmd = [
            "git",
            "--no-pager",
            "--no-replace-objects",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "credential.helper=",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "protocol.ext.allow=never",
            "-c",
            "protocol.ssh.allow=never",
            "-c",
            "color.ui=false",
            "-c",
            "core.quotepath=false",
            "-c",
            "i18n.logOutputEncoding=UTF-8",
            "-c",
            "log.showSignature=false",
            "-c",
            "log.mailmap=false",
            "-c",
            "diff.trustExitCode=false",
            *args,
        ]
        cmd_timeout = timeout if timeout is not None else self.default_timeout
        if cmd_timeout <= 0:
            raise ValueError("Git command timeout must be positive.")

        with tempfile.TemporaryDirectory(prefix="gitforensics_git_home_") as safe_home:
            try:
                process = subprocess.Popen(
                    full_cmd,
                    cwd=str(cwd) if cwd else None,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=self._safe_environment(safe_home),
                    shell=False,
                )
            except FileNotFoundError as err:
                raise GitForensicsError("Git executable was not found on system PATH.") from err

            assert process.stdout is not None
            assert process.stderr is not None
            stdout_data = bytearray()
            stderr_data = bytearray()
            overflow = threading.Event()
            threads = [
                threading.Thread(
                    target=self._drain_stream,
                    args=(
                        process.stdout,
                        stdout_data,
                        self.max_stdout_bytes,
                        overflow,
                        process,
                    ),
                    daemon=True,
                ),
                threading.Thread(
                    target=self._drain_stream,
                    args=(
                        process.stderr,
                        stderr_data,
                        self.max_stderr_bytes,
                        overflow,
                        process,
                    ),
                    daemon=True,
                ),
            ]
            for thread in threads:
                thread.start()
            try:
                process.wait(timeout=cmd_timeout)
            except subprocess.TimeoutExpired as err:
                process.kill()
                process.wait()
                for thread in threads:
                    thread.join(timeout=1.0)
                raise GitTimeoutError(
                    f"Git command timed out after {cmd_timeout}s: {args[0]}"
                ) from err
            for thread in threads:
                thread.join(timeout=1.0)

        if overflow.is_set():
            raise GitOutputLimitError("Git command output exceeded the configured byte limit.")

        stdout = bytes(stdout_data).decode("utf-8", errors="replace")
        stderr = bytes(stderr_data).decode("utf-8", errors="replace")

        result = GitCommandResult(
            command=full_cmd,
            stdout=stdout,
            stderr=stderr,
            returncode=process.returncode,
        )

        if check and process.returncode != 0:
            safe_stderr = sanitize_text(stderr.strip(), max_chars=2_000)
            raise GitCommandError(
                f"Git command failed with code {process.returncode}: {safe_stderr}",
                command=full_cmd,
                returncode=process.returncode,
                stderr=safe_stderr,
            )

        return result


class RepositoryExtractor:
    """Safely acquires and extracts commit history, tags, and workflows from a Git repository."""

    def __init__(
        self,
        runner: GitRunner | None = None,
        max_commits: int = 50000,
        clone_timeout: float = 120.0,
        limits: SecurityLimits | None = None,
    ) -> None:
        self.limits = limits or SecurityLimits(max_commits=max_commits)
        self.limits.validate()
        self.runner = runner or GitRunner(
            max_stdout_bytes=self.limits.max_git_stdout_bytes,
            max_stderr_bytes=self.limits.max_git_stderr_bytes,
        )
        self.max_commits = self.limits.max_commits
        self.clone_timeout = clone_timeout

    def extract(self, repo_input: RepositoryInput) -> ExtractedHistory:
        """Extracts history from a local directory or remote URL."""
        if repo_input.input_type == RepositoryInputType.REMOTE:
            return self._extract_remote(repo_input)
        else:
            return self._extract_local(Path(repo_input.resolved_path_or_url))

    def _extract_remote(self, repo_input: RepositoryInput) -> ExtractedHistory:
        tmp_path = Path(tempfile.mkdtemp(prefix="gitforensics_clone_"))
        result: ExtractedHistory | None = None
        try:
            self.runner.run(
                [
                    "clone",
                    "--no-checkout",
                    "--filter=blob:none",
                    "--no-recurse-submodules",
                    "--config",
                    f"core.hooksPath={os.devnull}",
                    "--",
                    repo_input.resolved_path_or_url,
                    str(tmp_path),
                ],
                timeout=self.clone_timeout,
            )
            result = self._extract_local(
                tmp_path,
                original_path_or_url=repo_input.resolved_path_or_url,
                consistency_check=False,
            )
        except (GitCommandError, GitTimeoutError, GitOutputLimitError) as err:
            raise GitCloneError("Failed to clone remote repository safely.") from err
        finally:
            try:
                shutil.rmtree(tmp_path, onerror=self._remove_readonly)
            except OSError as cleanup_error:
                raise TemporaryCleanupError(
                    "Temporary repository cleanup failed; manual cleanup is required."
                ) from cleanup_error
        assert result is not None
        return result

    @staticmethod
    def _remove_readonly(function: Callable[[str], Any], path: str, exc_info: object) -> None:
        """Make a read-only temporary Git object writable and retry its removal."""
        del exc_info
        try:
            os.chmod(path, 0o700)
            function(path)
        except OSError:
            raise

    def _extract_local(
        self,
        repo_path: Path,
        original_path_or_url: str | None = None,
        consistency_check: bool = True,
    ) -> ExtractedHistory:
        display_path = original_path_or_url or str(repo_path.resolve())
        warnings: list[str] = []

        try:
            rev_res = self.runner.run(
                ["rev-parse", "--git-dir", "--is-bare-repository"],
                cwd=repo_path,
                check=False,
            )
        except GitCommandError as err:
            raise InvalidGitRepositoryError(
                f"Directory is not a valid Git repository: {display_path}"
            ) from err

        if rev_res.returncode != 0:
            raise InvalidGitRepositoryError(
                f"Directory is not a valid Git repository: {display_path}"
            )

        lines = [line.strip() for line in rev_res.stdout.strip().splitlines() if line.strip()]
        git_dir = lines[0] if lines else ".git"
        is_bare = lines[1].lower() == "true" if len(lines) > 1 else False

        head_res = self.runner.run(
            ["rev-parse", "HEAD"],
            cwd=repo_path,
            check=False,
        )
        head_commit = (
            head_res.stdout.strip()
            if head_res.returncode == 0 and head_res.stdout.strip()
            else None
        )

        state_marker_start: RepositoryStateMarker | None = None
        if consistency_check:
            try:
                state_marker_start = self._build_state_marker(
                    repo_path,
                    head_commit=head_commit,
                    git_dir=git_dir,
                    is_bare=is_bare,
                )
                if state_marker_start.refs_truncated or state_marker_start.workflows_truncated:
                    warnings.append(
                        "Repository state marker reached the configured reference limit."
                    )
            except (GitForensicsError, OSError, ValueError):
                warnings.append("Repository state marker could not be captured at scan start.")

        if head_commit is None:
            return ExtractedHistory(
                repository_path=display_path,
                git_dir=git_dir,
                is_bare=is_bare,
                head_commit=None,
                commits=[],
                tags=[],
                workflows=[],
                warnings=warnings,
                state_marker_start=state_marker_start,
            )

        # Do not use %G? here: signature verification may execute a repository-configured
        # gpg/ssh helper. Extracted commits are intentionally recorded as unverified.
        format_str = "%H%x00%P%x00%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%T%x00%s"
        log_res = self.runner.run(
            [
                "log",
                "--all",
                "--topo-order",
                "--no-ext-diff",
                "--no-textconv",
                "--shortstat",
                f"--max-count={self.max_commits + 1}",
                f"--format=tformat:{format_str}",
            ],
            cwd=repo_path,
            check=False,
        )

        commits: list[CommitNode] = []
        commit_map: dict[str, CommitNode] = {}
        is_limited = False
        limit_reason = ""

        if log_res.returncode != 0:
            raise GitCommandError(
                "Git history traversal failed; repository may be corrupt.",
                command=log_res.command,
                returncode=log_res.returncode,
                stderr=sanitize_text(log_res.stderr, max_chars=2_000),
            )

        if log_res.stdout:
            records = self._parse_history_records(log_res.stdout, warnings)
            for fields, stat in records:
                commit_hash = fields[0].strip()
                if len(fields[1]) > 100_000:
                    warnings.append("Commit with excessive parent metadata was ignored.")
                    continue
                parents = [p.strip() for p in fields[1].split() if p.strip()]
                if len(parents) > 1_024:
                    warnings.append("Commit with excessive parent count was ignored.")
                    continue
                author_name = fields[2]
                author_email = fields[3]
                author_date_str = fields[4]
                committer_name = fields[5]
                committer_email = fields[6]
                committer_date_str = fields[7]
                tree_hash = fields[8]
                subject = fields[9]

                if not _HASH_PATTERN.fullmatch(commit_hash) or not _HASH_PATTERN.fullmatch(
                    tree_hash
                ):
                    warnings.append("Commit with invalid object identifier was ignored.")
                    continue
                if any(not _HASH_PATTERN.fullmatch(parent) for parent in parents):
                    warnings.append("Commit with invalid parent identifier was ignored.")
                    continue

                try:
                    author_date = datetime.fromisoformat(author_date_str.replace("Z", "+00:00"))
                    if author_date.tzinfo is None:
                        raise ValueError
                except (ValueError, OverflowError):
                    author_date = datetime.fromtimestamp(0, tz=UTC)
                    warnings.append("Commit with invalid author timestamp used a safe fallback.")

                try:
                    committer_date = datetime.fromisoformat(
                        committer_date_str.replace("Z", "+00:00")
                    )
                    if committer_date.tzinfo is None:
                        raise ValueError
                except (ValueError, OverflowError):
                    committer_date = datetime.fromtimestamp(0, tz=UTC)
                    warnings.append("Commit with invalid committer timestamp used a safe fallback.")

                commit_node = CommitNode(
                    hash=commit_hash,
                    parents=parents,
                    author_name=sanitize_text(author_name, max_chars=1_024, minimize_emails=False),
                    author_email=sanitize_text(
                        author_email, max_chars=1_024, minimize_emails=False
                    ),
                    author_date=author_date,
                    committer_name=sanitize_text(
                        committer_name, max_chars=1_024, minimize_emails=False
                    ),
                    committer_email=sanitize_text(
                        committer_email, max_chars=1_024, minimize_emails=False
                    ),
                    committer_date=committer_date,
                    subject=sanitize_text(subject, max_chars=4_096, minimize_emails=False),
                    body="",
                    tree_hash=tree_hash,
                    changed_files_count=stat[0],
                    insertions=stat[1],
                    deletions=stat[2],
                    signature_status=SignatureStatus.UNSIGNED,
                )
                commits.append(commit_node)
                commit_map[commit_hash] = commit_node

                if len(commits) > self.max_commits:
                    is_limited = True
                    limit_reason = f"Exceeded maximum commit limit of {self.max_commits}."
                    commits.pop()
                    commit_map.pop(commit_hash, None)
                    break

        tags = self._extract_tags(repo_path, commit_map, warnings)
        workflows = self._extract_local_workflows(repo_path, warnings)

        return ExtractedHistory(
            repository_path=display_path,
            git_dir=git_dir,
            is_bare=is_bare,
            head_commit=head_commit,
            commits=commits,
            tags=tags,
            workflows=workflows,
            is_limited=is_limited,
            limit_reason=limit_reason,
            warnings=warnings,
            state_marker_start=state_marker_start,
        )

    def capture_state_marker(self, repo_path: Path | str) -> RepositoryStateMarker:
        """Capture a bounded marker for a local repository without modifying it."""
        path = Path(repo_path)
        rev_res = self.runner.run(
            ["rev-parse", "--absolute-git-dir", "--is-bare-repository"],
            cwd=path,
            check=False,
        )
        if rev_res.returncode != 0:
            raise InvalidGitRepositoryError("Repository state could not be revalidated.")
        lines = [line.strip() for line in rev_res.stdout.splitlines() if line.strip()]
        if len(lines) < 2:
            raise InvalidGitRepositoryError("Repository state response was malformed.")
        head_res = self.runner.run(["rev-parse", "HEAD"], cwd=path, check=False)
        head = head_res.stdout.strip() if head_res.returncode == 0 else None
        if head and not _HASH_PATTERN.fullmatch(head):
            raise InvalidGitRepositoryError("Repository HEAD response was malformed.")
        return self._build_state_marker(
            path,
            head_commit=head,
            git_dir=lines[0],
            is_bare=lines[1].lower() == "true",
        )

    def _build_state_marker(
        self,
        repo_path: Path,
        *,
        head_commit: str | None,
        git_dir: str,
        is_bare: bool,
    ) -> RepositoryStateMarker:
        """Build the marker using a stable ref listing and filesystem directory identity."""
        git_dir_path = Path(git_dir)
        if not git_dir_path.is_absolute():
            git_dir_path = repo_path / git_dir_path
        resolved_git_dir = git_dir_path.resolve(strict=True)
        stat = resolved_git_dir.stat()
        identity_material = (
            f"{os.path.normcase(str(resolved_git_dir))}|{stat.st_dev}|{stat.st_ino}"
        ).encode("utf-8", errors="surrogatepass")
        git_dir_identity = hashlib.sha256(identity_material).hexdigest()

        refs_res = self.runner.run(
            [
                "for-each-ref",
                f"--count={self.limits.max_refs + 1}",
                "--sort=refname",
                "--format=%(refname)%00%(objectname)%00%(*objectname)",
            ],
            cwd=repo_path,
            check=False,
        )
        if refs_res.returncode != 0:
            raise GitCommandError(
                "Repository reference enumeration failed.",
                command=refs_res.command,
                returncode=refs_res.returncode,
                stderr=sanitize_text(refs_res.stderr, max_chars=2_000),
            )
        refs = [line.rstrip("\r") for line in refs_res.stdout.splitlines() if line]
        refs_truncated = len(refs) > self.limits.max_refs
        bounded_refs = refs[: self.limits.max_refs]
        digest = hashlib.sha256()
        for ref in bounded_refs:
            digest.update(ref.encode("utf-8", errors="surrogatepass"))
            digest.update(b"\n")
        workflow_digest, workflow_count, workflows_truncated = self._workflow_state_digest(
            repo_path, is_bare=is_bare
        )
        return RepositoryStateMarker(
            head_commit=head_commit,
            refs_digest=digest.hexdigest(),
            ref_count=len(bounded_refs),
            git_dir_identity=git_dir_identity,
            is_bare=is_bare,
            refs_truncated=refs_truncated,
            workflow_digest=workflow_digest,
            workflow_file_count=workflow_count,
            workflows_truncated=workflows_truncated,
        )

    def _workflow_state_digest(self, repo_path: Path, *, is_bare: bool) -> tuple[str, int, bool]:
        """Hash bounded workflow filesystem metadata without reading workflow content twice."""
        digest = hashlib.sha256()
        if is_bare:
            return digest.hexdigest(), 0, False
        workflow_dir = repo_path / ".github" / "workflows"
        if not workflow_dir.exists() or not workflow_dir.is_dir():
            return digest.hexdigest(), 0, False

        entries = nsmallest(
            self.limits.max_workflow_files + 1,
            (
                entry
                for entry in workflow_dir.iterdir()
                if entry.suffix.lower() in {".yml", ".yaml"}
            ),
            key=lambda entry: entry.name,
        )
        truncated = len(entries) > self.limits.max_workflow_files
        bounded_entries = entries[: self.limits.max_workflow_files]
        for entry in bounded_entries:
            stat = entry.lstat()
            metadata = (
                f"{entry.name}\0{stat.st_mode}\0{stat.st_size}\0{stat.st_mtime_ns}\0"
                f"{int(entry.is_symlink())}\n"
            )
            digest.update(metadata.encode("utf-8", errors="surrogatepass"))
        return digest.hexdigest(), len(bounded_entries), truncated

    def _parse_history_records(
        self, stdout: str, warnings: list[str]
    ) -> list[tuple[list[str], tuple[int, int, int]]]:
        """Parse one bounded log/shortstat traversal without constructing a line list."""
        records: list[tuple[list[str], tuple[int, int, int]]] = []
        current_fields: list[str] | None = None
        current_stat = (0, 0, 0)
        stat_entries = 0
        diff_warning_added = False

        for raw_line in io.StringIO(stdout):
            line = raw_line.rstrip("\r\n")
            if "\x00" in line:
                if current_fields is not None:
                    records.append((current_fields, current_stat))
                fields = line.split("\x00")
                if len(fields) != 10:
                    warnings.append("Malformed Git log record was ignored.")
                    current_fields = None
                    current_stat = (0, 0, 0)
                    continue
                current_fields = fields
                current_stat = (0, 0, 0)
                continue
            if current_fields is None or not line.strip():
                continue
            files_match = _SHORTSTAT_FILES_RE.search(line)
            if files_match:
                stat_entries += 1
                if stat_entries > self.limits.max_diff_entries:
                    if not diff_warning_added:
                        warnings.append(
                            f"Commit statistics limited to {self.limits.max_diff_entries} entries."
                        )
                        diff_warning_added = True
                    continue
                insertion_match = _SHORTSTAT_INSERTIONS_RE.search(line)
                deletion_match = _SHORTSTAT_DELETIONS_RE.search(line)
                current_stat = (
                    int(files_match.group(1)),
                    int(insertion_match.group(1)) if insertion_match else 0,
                    int(deletion_match.group(1)) if deletion_match else 0,
                )

        if current_fields is not None:
            records.append((current_fields, current_stat))
        return records

    def _extract_tags(
        self,
        repo_path: Path,
        commit_map: dict[str, CommitNode],
        warnings: list[str],
    ) -> list[TagNode]:
        """Extracts tag references, peeled target hashes, and tagger metadata."""
        tag_fmt = (
            "%(refname)\x1f%(objectname)\x1f%(objecttype)\x1f"
            "%(*objectname)\x1f%(*objecttype)\x1f%(taggername)\x1f"
            "%(taggeremail)\x1f%(taggerdate:iso-strict)\x1f%(contents:subject)\x1e"
        )
        res = self.runner.run(
            [
                "for-each-ref",
                f"--count={self.limits.max_tags + 1}",
                f"--format={tag_fmt}",
                "refs/tags",
            ],
            cwd=repo_path,
            check=False,
        )

        if res.returncode != 0:
            warnings.append("Tag enumeration failed; tag analysis is incomplete.")
            return []
        if not res.stdout.strip():
            return []

        tags: list[TagNode] = []
        for rec in res.stdout.split("\x1e"):
            rec = rec.strip("\r\n")
            if not rec:
                continue

            fields = rec.split("\x1f")
            if len(fields) < 9:
                warnings.append("Malformed tag record was ignored.")
                continue

            ref_name = fields[0]
            short_name = ref_name.replace("refs/tags/", "")
            target_hash = fields[1]
            target_type = fields[2]
            peeled_hash = fields[3] if fields[3] else None
            peeled_type = fields[4] if fields[4] else None
            tagger_name = fields[5]
            tagger_email = fields[6]
            tagger_date_str = fields[7]
            message = fields[8]

            is_annotated = target_type == "tag"
            resolved_commit = (
                peeled_hash if (peeled_type == "commit" or not peeled_type) else target_hash
            )

            tagger_date: datetime | None = None
            if tagger_date_str:
                try:
                    tagger_date = datetime.fromisoformat(tagger_date_str.replace("Z", "+00:00"))
                except ValueError:
                    tagger_date = None

            commit_dt: datetime | None = None
            if resolved_commit and resolved_commit in commit_map:
                commit_dt = commit_map[resolved_commit].committer_date

            if len(tags) >= self.limits.max_tags:
                warnings.append(f"Tag analysis limited to {self.limits.max_tags} tags.")
                break
            if not _HASH_PATTERN.fullmatch(target_hash):
                warnings.append("Tag with invalid object identifier was ignored.")
                continue

            tags.append(
                TagNode(
                    ref_name=sanitize_text(ref_name, max_chars=1_024, minimize_emails=False),
                    short_name=sanitize_text(short_name, max_chars=1_024, minimize_emails=False),
                    target_hash=target_hash,
                    target_type=target_type,
                    peeled_commit_hash=resolved_commit,
                    is_annotated=is_annotated,
                    tagger_name=sanitize_text(tagger_name, max_chars=1_024, minimize_emails=False),
                    tagger_email=sanitize_text(
                        tagger_email, max_chars=1_024, minimize_emails=False
                    ),
                    tagger_date=tagger_date,
                    message=sanitize_text(message, max_chars=4_096, minimize_emails=False),
                    signature_status=SignatureStatus.UNSIGNED,
                    commit_date=commit_dt,
                )
            )

        return tags

    def _extract_local_workflows(self, repo_path: Path, warnings: list[str]) -> list[WorkflowFile]:
        """Safely extracts workflow files from .github/workflows directory if present."""
        workflows_dir = repo_path / ".github" / "workflows"
        if not workflows_dir.exists() or not workflows_dir.is_dir():
            return []

        workflows: list[WorkflowFile] = []
        resolved_root = workflows_dir.resolve()
        workflow_candidates = nsmallest(
            self.limits.max_workflow_files + 1,
            (
                entry
                for entry in workflows_dir.iterdir()
                if entry.suffix.lower() in (".yml", ".yaml")
            ),
            key=lambda entry: entry.name,
        )
        if len(workflow_candidates) > self.limits.max_workflow_files:
            warnings.append(f"Workflow analysis limited to {self.limits.max_workflow_files} files.")
        for wf_file in workflow_candidates[: self.limits.max_workflow_files]:
            try:
                if wf_file.is_symlink() or not wf_file.is_file():
                    warnings.append("Symbolic-link workflow file was ignored.")
                    continue
                resolved_file = wf_file.resolve(strict=True)
                if os.path.commonpath((str(resolved_root), str(resolved_file))) != str(
                    resolved_root
                ):
                    warnings.append("Workflow path escaped its repository directory.")
                    continue
                with resolved_file.open("rb") as workflow_stream:
                    raw = workflow_stream.read(self.limits.max_workflow_file_bytes + 1)
                if len(raw) > self.limits.max_workflow_file_bytes:
                    warnings.append(f"Oversized workflow '{wf_file.name}' was ignored.")
                    continue
                content = raw.decode("utf-8", errors="replace")
                safe_name = sanitize_text(wf_file.name, max_chars=255, minimize_emails=False)
                workflows.append(
                    WorkflowFile(
                        path=f".github/workflows/{safe_name}",
                        name=safe_name,
                        content=content,
                        lines=content.splitlines(),
                    )
                )
            except (OSError, UnicodeError):
                warnings.append("Unreadable workflow file was ignored.")
                continue
        return workflows
