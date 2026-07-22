"""Bounded per-analysis derived indexes shared by independent detectors."""

from collections import Counter, defaultdict
from types import MappingProxyType

from gitforensics.models import AnalysisSummary, RepositoryContext, TagNode


def _identity(email: str, name: str) -> str:
    """Normalize an identity once for all detectors in the current run."""
    return email.strip().lower() or name.strip().lower()


def build_analysis_summary(context: RepositoryContext) -> AnalysisSummary:
    """Build immutable indexes and stable statistics from already-bounded history."""
    commits = context.history.commits
    commits_by_author = tuple(sorted(commits, key=lambda commit: commit.author_date))
    commits_by_committer = tuple(sorted(commits, key=lambda commit: commit.committer_date))
    non_merges = tuple(commit for commit in commits_by_author if not commit.is_merge)
    commit_by_hash = {commit.hash: commit for commit in commits}
    commit_index = {commit.hash: index for index, commit in enumerate(commits)}
    authors = tuple(_identity(commit.author_email, commit.author_name) for commit in commits)
    committers = tuple(
        _identity(commit.committer_email, commit.committer_name) for commit in commits
    )
    counts = Counter(authors)
    author_counts = tuple(sorted(counts.items(), key=lambda item: (-item[1], item[0])))

    tags_by_target_mutable: dict[str, list[TagNode]] = defaultdict(list)
    tags_by_name: dict[str, TagNode] = {}
    for tag in context.history.tags:
        target = tag.peeled_commit_hash or tag.target_hash
        tags_by_target_mutable[target].append(tag)
        tags_by_name[tag.short_name] = tag
    tags_by_target = {
        target: tuple(tags) for target, tags in sorted(tags_by_target_mutable.items())
    }

    return AnalysisSummary(
        commits_by_author_date=commits_by_author,
        commits_by_committer_date=commits_by_committer,
        non_merge_commits_by_author_date=non_merges,
        commit_by_hash=MappingProxyType(commit_by_hash),
        commit_index_by_hash=MappingProxyType(commit_index),
        root_commits=tuple(commit for commit in commits if commit.is_root),
        normalized_author_identities=authors,
        normalized_committer_identities=committers,
        author_counts=author_counts,
        total_changed_files=sum(commit.changed_files_count for commit in commits),
        total_insertions=sum(commit.insertions for commit in commits),
        total_deletions=sum(commit.deletions for commit in commits),
        earliest_committer_date=(commits_by_committer[0].committer_date if commits else None),
        latest_committer_date=(commits_by_committer[-1].committer_date if commits else None),
        tags_by_target=MappingProxyType(tags_by_target),
        tags_by_name=MappingProxyType(tags_by_name),
    )


def get_analysis_summary(context: RepositoryContext) -> AnalysisSummary:
    """Return the run-local summary, building it once for library-created contexts."""
    summary = context.analysis_summary
    if summary is None:
        summary = build_analysis_summary(context)
        context.analysis_summary = summary
    return summary
