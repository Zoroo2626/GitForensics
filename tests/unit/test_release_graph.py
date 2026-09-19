"""Release ancestry must follow Git parent edges, independent of log ordering."""

from dataclasses import replace

import pytest

from gitforensics.detectors.remote.release_provenance import (
    AssetHeavyMinimalSourceDetector,
    ReleaseChronologyConflictDetector,
)
from gitforensics.models import CommitNode, Severity
from gitforensics.release_analysis import (
    compute_inter_release_diff,
    parse_release_from_api,
    resolve_release_to_history,
    run_release_analysis,
)
from gitforensics.release_models import ReleaseRecord
from tests.helpers.git_fixtures import make_synthetic_commit, make_synthetic_context


def _graph() -> dict[str, CommitNode]:
    return {
        key: make_synthetic_commit(
            commit_hash=key * 40,
            parents=[parent * 40 for parent in parents],
            changed_files_count=files,
            insertions=insertions,
            deletions=deletions,
        )
        for key, parents, files, insertions, deletions in (
            ("a", "", 10, 100, 50),
            ("b", "a", 1, 1, 2),
            ("c", "a", 2, 2, 3),
            ("d", "bc", 0, 0, 0),
        )
    }


def _release(number: int, target: str, name: str | None = None) -> ReleaseRecord:
    return parse_release_from_api(
        {
            "id": number,
            "name": name or f"v{number}.0.0",
            "tag_name": f"release-{number}",
            "target_commitish": target * 40,
            "published_at": f"2026-01-{number:02d}T00:00:00Z",
        }
    )


@pytest.mark.parametrize("order", ["bca", "cba", "abc"])
def test_branch_reachability_and_delta_ignore_log_order(order: str) -> None:
    graph = _graph()
    context = make_synthetic_context([graph[key] for key in order])
    context.history.head_commit = graph["b"].hash
    side = resolve_release_to_history(_release(1, "c"), context.history)
    assert not side.is_reachable_from_default_branch
    assert side.is_reachable_from_any_ref
    root = resolve_release_to_history(_release(1, "a"), context.history)
    assert root.is_reachable_from_default_branch
    assert root.is_reachable_from_any_ref
    result = run_release_analysis([_release(1, "a"), _release(2, "b")], context.history, "o", "r")
    delta = result.releases[1]
    assert delta.commits_since_prev == 1
    assert delta.files_changed_since_prev == 1
    assert delta.insertions_since_prev == 1
    assert delta.deletions_since_prev == 2


@pytest.mark.parametrize(
    ("previous", "current", "counts"),
    [
        ("b", "c", (1, 2, 2, 3)),  # Switch to a sibling branch.
        ("b", "d", (2, 2, 2, 3)),  # Merge adds the side commit and merge commit once.
        ("a", "d", (3, 3, 3, 5)),  # Shared root is excluded and never double counted.
        ("d", "b", (0, 0, 0, 0)),  # A rollback adds no previously unseen commits.
        ("b", "b", (0, 0, 0, 0)),
    ],
)
def test_release_deltas_follow_ancestor_set_difference(
    previous: str, current: str, counts: tuple[int, int, int, int]
) -> None:
    context = make_synthetic_context(list(_graph().values()))
    result = run_release_analysis(
        [_release(1, previous), _release(2, current)], context.history, "o", "r"
    )
    delta = result.releases[1]
    assert (
        delta.commits_since_prev,
        delta.files_changed_since_prev,
        delta.insertions_since_prev,
        delta.deletions_since_prev,
    ) == counts
    assert not result.incomplete


def test_missing_ancestry_is_unknown_and_does_not_become_a_first_release() -> None:
    graph = _graph()
    context = make_synthetic_context([graph["b"], graph["c"]])  # Shared parent not extracted.
    result = run_release_analysis([_release(1, "b"), _release(2, "c")], context.history, "o", "r")
    assert result.incomplete
    delta = result.releases[1]
    assert delta.commits_since_prev is None
    assert delta.insertions_since_prev is None
    delta.release.assets = parse_release_from_api(
        {"assets": [{"id": 1, "name": "app.zip", "size": 500_000_000}]}
    ).assets
    context.release_analysis_result = result
    assert AssetHeavyMinimalSourceDetector().analyze(context).findings == []


def test_recomputing_delta_clears_stale_statistics() -> None:
    graph = _graph()
    context = make_synthetic_context(list(graph.values()))
    result = run_release_analysis([_release(1, "a"), _release(2, "b")], context.history, "o", "r")
    newer = result.releases[1]
    compute_inter_release_diff([newer], context.history)
    assert newer.prev_resolved_commit is None
    assert newer.commits_since_prev is None
    assert newer.files_changed_since_prev is None
    assert newer.insertions_since_prev is None
    assert newer.deletions_since_prev is None


@pytest.mark.parametrize(("target", "severity"), [("c", Severity.LOW), ("a", Severity.MEDIUM)])
def test_chronology_only_confirms_actual_ancestry(target: str, severity: Severity) -> None:
    graph = _graph()
    context = make_synthetic_context([graph[key] for key in "bca"])
    context.release_analysis_result = run_release_analysis(
        [_release(1, "b", "v2.0.0"), _release(2, target, "v1.0.0")],
        context.history,
        "o",
        "r",
    )
    findings = ReleaseChronologyConflictDetector().analyze(context).findings
    assert len(findings) == 1
    assert findings[0].severity == severity


def test_same_commit_delta_is_zero_even_with_missing_ancestors() -> None:
    graph = _graph()
    context = make_synthetic_context([graph["b"]])
    result = run_release_analysis([_release(1, "b"), _release(2, "b")], context.history, "o", "r")
    assert result.releases[1].commits_since_prev == 0
    assert not result.incomplete


def test_parent_walk_terminates_even_on_malformed_cyclic_input() -> None:
    graph = _graph()
    context = make_synthetic_context([replace(graph["a"], parents=[graph["b"].hash]), graph["b"]])
    resolved = resolve_release_to_history(_release(1, "b"), context.history)
    assert resolved.is_reachable_from_default_branch
