"""GF008: History modifying workflow detector."""

import re

from gitforensics.detectors.base import BaseDetector
from gitforensics.models import (
    Confidence,
    DetectorResult,
    Evidence,
    Finding,
    RepositoryContext,
    Severity,
)
from gitforensics.security import sanitize_text

REDACT_PATTERNS = (
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    re.compile(r"github_pat_[a-zA-Z0-9_]{82}"),
    re.compile(r"(Bearer\s+)[A-Za-z0-9_.-]+", re.IGNORECASE),
    re.compile(r"(token:\s*)[^\s]+", re.IGNORECASE),
    re.compile(r"(secret[s]?\.[A-Za-z0-9_]+)", re.IGNORECASE),
)

FORCE_PUSH_PATTERN = re.compile(
    r"\bgit\s+push\s+.*(--force|-f|--force-with-lease)\b", re.IGNORECASE
)
REWRITE_HISTORY_PATTERN = re.compile(
    r"\bgit\s+(reset\s+--hard|filter-branch|filter-repo|replace|commit\s+--amend)\b",
    re.IGNORECASE,
)
NORMAL_PUSH_PATTERN = re.compile(r"\bgit\s+push\b", re.IGNORECASE)
SCHEDULE_PATTERN = re.compile(r"schedule:\s*-\s*cron:", re.IGNORECASE)
WRITE_ALL_PATTERN = re.compile(r"permissions:\s*write-all", re.IGNORECASE)
CONTENTS_WRITE_PATTERN = re.compile(r"contents:\s*write", re.IGNORECASE)


def sanitize_snippet(line: str) -> str:
    """Redacts tokens, credentials, and secrets from workflow line snippet."""
    sanitized = line.strip()
    for pat in REDACT_PATTERNS:
        sanitized = pat.sub(r"\1[REDACTED]" if pat.groups > 0 else "[REDACTED]", sanitized)
    return sanitize_text(sanitized, max_chars=200)


class HistoryModifyingWorkflowsDetector(BaseDetector):
    """Detects GitHub Actions workflows containing commands or permissions modifying Git history."""

    def get_rule_id(self) -> str:
        return "GF008"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        workflows = context.history.workflows
        if not workflows:
            return DetectorResult(
                rule_id=self.get_rule_id(),
                skipped=True,
                skip_reason="No workflow files found.",
            )

        findings: list[Finding] = []

        for wf in workflows:
            content = wf.content
            lines = wf.lines
            is_scheduled = bool(SCHEDULE_PATTERN.search(content))
            has_write_permission = bool(
                WRITE_ALL_PATTERN.search(content) or CONTENTS_WRITE_PATTERN.search(content)
            )

            for line_idx, line in enumerate(lines, start=1):
                clean_snippet = sanitize_snippet(line)

                # 1. Force push or force-with-lease
                if FORCE_PUSH_PATTERN.search(line):
                    severity = Severity.CRITICAL if is_scheduled else Severity.HIGH
                    evidence = Evidence(
                        data={
                            "workflow_path": wf.path,
                            "workflow_name": wf.name,
                            "line_number": line_idx,
                            "snippet": clean_snippet,
                            "force_push": True,
                            "is_scheduled": is_scheduled,
                            "has_write_permission": has_write_permission,
                        }
                    )
                    findings.append(
                        Finding(
                            rule_id=self.get_rule_id(),
                            title="Workflow Force Push Command",
                            description=(
                                f"Workflow '{wf.path}' line {line_idx} contains "
                                f"a Git force push command."
                            ),
                            severity=severity,
                            confidence=Confidence.HIGH,
                            evidence=evidence,
                        )
                    )
                    if len(findings) >= context.security_limits.max_findings:
                        return DetectorResult(
                            rule_id=self.get_rule_id(),
                            findings=findings,
                            truncated=True,
                            truncation_reason="GF008 findings reached the configured limit.",
                        )

                # 2. History rewrite commands (reset --hard, filter-branch, etc.)
                elif REWRITE_HISTORY_PATTERN.search(line):
                    evidence = Evidence(
                        data={
                            "workflow_path": wf.path,
                            "workflow_name": wf.name,
                            "line_number": line_idx,
                            "snippet": clean_snippet,
                            "history_rewrite": True,
                            "is_scheduled": is_scheduled,
                        }
                    )
                    findings.append(
                        Finding(
                            rule_id=self.get_rule_id(),
                            title="Workflow History Rewrite Command",
                            description=(
                                f"Workflow '{wf.path}' line {line_idx} contains "
                                f"a Git history rewrite command."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            evidence=evidence,
                        )
                    )
                    if len(findings) >= context.security_limits.max_findings:
                        return DetectorResult(
                            rule_id=self.get_rule_id(),
                            findings=findings,
                            truncated=True,
                            truncation_reason="GF008 findings reached the configured limit.",
                        )

                # 3. Scheduled automated push
                elif is_scheduled and NORMAL_PUSH_PATTERN.search(line):
                    evidence = Evidence(
                        data={
                            "workflow_path": wf.path,
                            "workflow_name": wf.name,
                            "line_number": line_idx,
                            "snippet": clean_snippet,
                            "scheduled_push": True,
                        }
                    )
                    findings.append(
                        Finding(
                            rule_id=self.get_rule_id(),
                            title="Scheduled Automated Commit/Push Workflow",
                            description=(
                                f"Workflow '{wf.path}' line {line_idx} contains "
                                f"a push command inside a scheduled cron workflow."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            evidence=evidence,
                        )
                    )
                    if len(findings) >= context.security_limits.max_findings:
                        return DetectorResult(
                            rule_id=self.get_rule_id(),
                            findings=findings,
                            truncated=True,
                            truncation_reason="GF008 findings reached the configured limit.",
                        )

        return DetectorResult(rule_id=self.get_rule_id(), findings=findings)
