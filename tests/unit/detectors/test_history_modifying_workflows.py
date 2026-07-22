"""Unit tests for GF008: History modifying workflow detector."""

from gitforensics.detectors.local.history_modifying_workflows import (
    HistoryModifyingWorkflowsDetector,
)
from gitforensics.models import Severity, WorkflowFile
from tests.helpers.git_fixtures import make_synthetic_context


def test_workflow_force_push_command() -> None:
    """Test detection of git push --force in workflow file."""
    content = (
        "name: Deploy\n"
        "on: push\n"
        "jobs:\n"
        "  deploy:\n"
        "    steps:\n"
        "      - run: git push --force origin main\n"
    )
    wf = WorkflowFile(
        path=".github/workflows/deploy.yml",
        name="deploy.yml",
        content=content,
        lines=content.splitlines(),
    )
    context = make_synthetic_context([])
    context.history.workflows = [wf]

    detector = HistoryModifyingWorkflowsDetector()
    res = detector.analyze(context)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.rule_id == "GF008"
    assert f.severity == Severity.HIGH
    assert f.evidence.data["force_push"] is True


def test_scheduled_workflow_force_push_critical_severity() -> None:
    """Test scheduled cron workflow force pushing yields CRITICAL severity."""
    content = (
        "name: Nightly Sync\n"
        "on:\n"
        "  schedule:\n"
        "    - cron: '0 0 * * *'\n"
        "jobs:\n"
        "  sync:\n"
        "    steps:\n"
        "      - run: git push -f origin main\n"
    )
    wf = WorkflowFile(
        path=".github/workflows/sync.yml",
        name="sync.yml",
        content=content,
        lines=content.splitlines(),
    )
    context = make_synthetic_context([])
    context.history.workflows = [wf]

    detector = HistoryModifyingWorkflowsDetector()
    res = detector.analyze(context)
    assert len(res.findings) == 1
    assert res.findings[0].severity == Severity.CRITICAL


def test_credential_redaction_in_snippets() -> None:
    """Test sensitive tokens are redacted from evidence snippets."""
    token = "ghp_" + "e" * 36
    content = (
        "name: Push with token\n"
        "on: push\n"
        "jobs:\n"
        "  push:\n"
        "    steps:\n"
        f"      - run: git push --force https://{token}@github.com/repo.git\n"
    )
    wf = WorkflowFile(
        path=".github/workflows/token.yml",
        name="token.yml",
        content=content,
        lines=content.splitlines(),
    )
    context = make_synthetic_context([])
    context.history.workflows = [wf]

    detector = HistoryModifyingWorkflowsDetector()
    res = detector.analyze(context)
    assert len(res.findings) == 1
    snippet = res.findings[0].evidence.data["snippet"]
    assert token not in snippet
    assert "[REDACTED]" in snippet


def test_workflow_no_git_commands_no_finding() -> None:
    """Test harmless workflow without git commands produces no finding."""
    content = "name: CI\non: push\njobs:\n  test:\n    steps:\n      - run: pytest\n"
    wf = WorkflowFile(
        path=".github/workflows/ci.yml",
        name="ci.yml",
        content=content,
        lines=content.splitlines(),
    )
    context = make_synthetic_context([])
    context.history.workflows = [wf]

    detector = HistoryModifyingWorkflowsDetector()
    res = detector.analyze(context)
    assert len(res.findings) == 0
