"""Helper functions for creating synthetic Git test repositories and in-memory contexts."""

import os
import subprocess
from datetime import datetime
from pathlib import Path

from gitforensics.compat import UTC
from gitforensics.models import (
    CommitNode,
    ExtractedHistory,
    RepositoryContext,
    RepositoryInput,
    RepositoryInputType,
    SignatureStatus,
)


def make_synthetic_context(commits: list[CommitNode]) -> RepositoryContext:
    """Helper to wrap a list of CommitNodes in a valid RepositoryContext."""
    inp = RepositoryInput(
        raw_input="/path/to/synthetic",
        input_type=RepositoryInputType.LOCAL,
        resolved_path_or_url="/path/to/synthetic",
    )
    history = ExtractedHistory(
        repository_path="/path/to/synthetic",
        git_dir=".git",
        is_bare=False,
        head_commit=commits[0].hash if commits else None,
        commits=commits,
    )
    return RepositoryContext(input=inp, history=history)


def make_synthetic_commit(
    commit_hash: str = "hash1",
    parents: list[str] | None = None,
    author_name: str = "Alice",
    author_email: str = "alice@example.com",
    author_date: datetime | None = None,
    committer_name: str = "Alice",
    committer_email: str = "alice@example.com",
    committer_date: datetime | None = None,
    subject: str = "Synthetic commit",
    body: str = "",
    tree_hash: str = "tree1",
    changed_files_count: int = 1,
    insertions: int = 10,
    deletions: int = 0,
    signature_status: SignatureStatus = SignatureStatus.UNSIGNED,
) -> CommitNode:
    """Helper to construct a typed CommitNode for synthetic unit testing."""
    dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    return CommitNode(
        hash=commit_hash,
        parents=parents if parents is not None else [],
        author_name=author_name,
        author_email=author_email,
        author_date=author_date if author_date is not None else dt,
        committer_name=committer_name,
        committer_email=committer_email,
        committer_date=committer_date if committer_date is not None else dt,
        subject=subject,
        body=body,
        tree_hash=tree_hash,
        changed_files_count=changed_files_count,
        insertions=insertions,
        deletions=deletions,
        signature_status=signature_status,
    )


def create_dummy_repo(
    path: Path,
    bare: bool = False,
) -> None:
    """Initializes a new dummy Git repository with isolated config."""
    env = dict(os.environ)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"

    cmd = ["git", "init"]
    if bare:
        cmd.append("--bare")
    cmd.append(str(path))

    subprocess.run(cmd, check=True, capture_output=True, env=env, shell=False)

    if not bare:
        subprocess.run(
            ["git", "config", "user.name", "Test Author"],
            cwd=str(path),
            check=True,
            env=env,
            shell=False,
        )
        subprocess.run(
            ["git", "config", "user.email", "author@example.com"],
            cwd=str(path),
            check=True,
            env=env,
            shell=False,
        )


def add_commit(
    path: Path,
    filename: str = "file.txt",
    content: str = "content\n",
    message: str = "Test commit",
    author_name: str = "Test Author",
    author_email: str = "author@example.com",
    author_date: str = "2026-01-01T12:00:00+00:00",
    committer_name: str = "Test Committer",
    committer_email: str = "committer@example.com",
    committer_date: str = "2026-01-01T12:00:00+00:00",
) -> str:
    """Creates a file, stages it, and creates a commit with explicit identities/dates."""
    file_path = path / filename
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")

    env = dict(os.environ)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    env["GIT_AUTHOR_NAME"] = author_name
    env["GIT_AUTHOR_EMAIL"] = author_email
    env["GIT_AUTHOR_DATE"] = author_date
    env["GIT_COMMITTER_NAME"] = committer_name
    env["GIT_COMMITTER_EMAIL"] = committer_email
    env["GIT_COMMITTER_DATE"] = committer_date

    subprocess.run(
        ["git", "add", str(file_path)],
        cwd=str(path),
        check=True,
        capture_output=True,
        env=env,
        shell=False,
    )
    subprocess.run(
        ["git", "commit", "-m", message],
        cwd=str(path),
        check=True,
        capture_output=True,
        env=env,
        shell=False,
    )

    res = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(path),
        check=True,
        capture_output=True,
        text=True,
        env=env,
        shell=False,
    )
    return res.stdout.strip()
