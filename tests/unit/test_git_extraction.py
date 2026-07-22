"""Unit tests for repository extraction, edge cases, commit models, and serialization."""

import os
import subprocess
from pathlib import Path

from gitforensics.git import RepositoryExtractor, parse_repository_input
from tests.helpers.git_fixtures import add_commit, create_dummy_repo


def test_empty_repository(tmp_path: Path) -> None:
    """Test requirement 9: empty repository handling."""
    create_dummy_repo(tmp_path)
    repo_input = parse_repository_input(str(tmp_path))
    extractor = RepositoryExtractor()
    history = extractor.extract(repo_input)

    assert history.head_commit is None
    assert history.commits == []
    assert not history.is_bare


def test_one_commit_repository(tmp_path: Path) -> None:
    """Test requirement 4: repository with one commit."""
    create_dummy_repo(tmp_path)
    c1_hash = add_commit(tmp_path, message="Initial commit")

    repo_input = parse_repository_input(str(tmp_path))
    history = RepositoryExtractor().extract(repo_input)

    assert len(history.commits) == 1
    c1 = history.commits[0]
    assert c1.hash == c1_hash
    assert c1.subject == "Initial commit"
    assert c1.is_root
    assert not c1.is_merge
    assert c1.changed_files_count == 1
    assert c1.insertions > 0


def test_multiple_commits_and_deterministic_ordering(tmp_path: Path) -> None:
    """Test requirements 5 & 25: multiple commits and deterministic ordering."""
    create_dummy_repo(tmp_path)
    h1 = add_commit(
        tmp_path,
        filename="f1.txt",
        message="Commit 1",
        author_date="2026-01-01T10:00:00Z",
    )
    h2 = add_commit(
        tmp_path,
        filename="f2.txt",
        message="Commit 2",
        author_date="2026-01-02T10:00:00Z",
    )
    h3 = add_commit(
        tmp_path,
        filename="f3.txt",
        message="Commit 3",
        author_date="2026-01-03T10:00:00Z",
    )

    repo_input = parse_repository_input(str(tmp_path))
    history = RepositoryExtractor().extract(repo_input)

    assert len(history.commits) == 3
    extracted_hashes = [c.hash for c in history.commits]
    assert extracted_hashes == [h3, h2, h1]


def test_merge_commit_extraction(tmp_path: Path) -> None:
    """Test requirement 6: merge commit extraction."""
    create_dummy_repo(tmp_path)
    add_commit(tmp_path, filename="main.txt", message="Main 1")

    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    subprocess.run(
        ["git", "checkout", "-b", "feature"],
        cwd=str(tmp_path),
        check=True,
        env=env,
        shell=False,
    )
    add_commit(tmp_path, filename="feature.txt", message="Feature commit")

    subprocess.run(
        ["git", "checkout", "master"],
        cwd=str(tmp_path),
        check=True,
        env=env,
        shell=False,
    )
    add_commit(tmp_path, filename="main2.txt", message="Main 2")

    subprocess.run(
        ["git", "merge", "--no-ff", "feature", "-m", "Merge feature"],
        cwd=str(tmp_path),
        check=True,
        env=env,
        shell=False,
    )

    repo_input = parse_repository_input(str(tmp_path))
    history = RepositoryExtractor().extract(repo_input)

    merge_commit = history.commits[0]
    assert merge_commit.is_merge
    assert len(merge_commit.parents) == 2


def test_multiple_branches_and_detached_head(tmp_path: Path) -> None:
    """Test requirements 7 & 8: multiple branches and detached HEAD."""
    create_dummy_repo(tmp_path)
    c1 = add_commit(tmp_path, filename="f1.txt", message="C1")

    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    subprocess.run(
        ["git", "checkout", "-b", "dev"],
        cwd=str(tmp_path),
        check=True,
        env=env,
        shell=False,
    )
    add_commit(tmp_path, filename="dev.txt", message="Dev C2")

    subprocess.run(["git", "checkout", c1], cwd=str(tmp_path), check=True, env=env, shell=False)

    repo_input = parse_repository_input(str(tmp_path))
    history = RepositoryExtractor().extract(repo_input)

    assert history.head_commit == c1
    assert len(history.commits) == 2


def test_bare_repository(tmp_path: Path) -> None:
    """Test requirement 10: bare repository history extraction."""
    src_repo = tmp_path / "src"
    create_dummy_repo(src_repo)
    add_commit(src_repo, message="Bare test commit")

    bare_repo = tmp_path / "bare.git"
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    subprocess.run(
        ["git", "clone", "--bare", str(src_repo), str(bare_repo)],
        check=True,
        env=env,
        shell=False,
    )

    repo_input = parse_repository_input(str(bare_repo))
    history = RepositoryExtractor().extract(repo_input)

    assert history.is_bare
    assert len(history.commits) == 1
    assert history.commits[0].subject == "Bare test commit"


def test_unicode_names_and_messages(tmp_path: Path) -> None:
    """Test requirement 11: Unicode author names and commit messages."""
    create_dummy_repo(tmp_path)
    add_commit(
        tmp_path,
        message="コミットメッセージ 🚀 (Unicode test)",
        author_name="山田太郎 太郎",
        author_email="yamada@example.jp",
    )

    repo_input = parse_repository_input(str(tmp_path))
    history = RepositoryExtractor().extract(repo_input)

    c = history.commits[0]
    assert c.author_name == "山田太郎 太郎"
    assert "コミットメッセージ" in c.subject
    assert "🚀" in c.subject


def test_different_author_and_committer_identities_and_timestamps(
    tmp_path: Path,
) -> None:
    """Test requirements 12 & 13: distinct author/committer identities and timestamps."""
    create_dummy_repo(tmp_path)
    add_commit(
        tmp_path,
        message="Identity Mismatch Commit",
        author_name="Alice Author",
        author_email="alice@example.com",
        author_date="2026-01-01T08:00:00+02:00",
        committer_name="Bob Committer",
        committer_email="bob@example.com",
        committer_date="2026-01-02T12:00:00+00:00",
    )

    repo_input = parse_repository_input(str(tmp_path))
    history = RepositoryExtractor().extract(repo_input)

    c = history.commits[0]
    assert c.author_name == "Alice Author"
    assert c.committer_name == "Bob Committer"
    assert c.author_date != c.committer_date


def test_commit_model_serialization(tmp_path: Path) -> None:
    """Test requirement 24: serialization of extracted commit models."""
    create_dummy_repo(tmp_path)
    add_commit(tmp_path, message="Serializable commit")

    repo_input = parse_repository_input(str(tmp_path))
    history = RepositoryExtractor().extract(repo_input)

    data = history.to_dict()
    assert data["total_commits"] == 1
    assert data["commits"][0]["subject"] == "Serializable commit"
    assert "author_date" in data["commits"][0]
    assert "committer_date" in data["commits"][0]
