"""Reporting and output formatting module for GitForensics."""

import json
import os
import tempfile
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from gitforensics import __version__
from gitforensics.errors import CLIArgumentError, OutputWriteError
from gitforensics.models import AnalysisReport, OutputFormat, Severity
from gitforensics.security import safe_output_path, sanitize_text

SEVERITY_COLORS = MappingProxyType(
    {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim white",
    }
)


def render_report(
    report: AnalysisReport,
    output_format: OutputFormat = OutputFormat.TEXT,
    no_color: bool = False,
    quiet: bool = False,
    verbose: bool = False,
) -> str:
    """Renders the analysis report in terminal or JSON format."""
    safe_report = report.to_dict()
    if output_format == OutputFormat.JSON:
        return json.dumps(safe_report, indent=2, sort_keys=True, ensure_ascii=False)

    console = Console(record=True, width=100, no_color=no_color, highlight=False)
    safe_repository = escape(str(safe_report["repository"]))

    # Title panel
    console.print(
        Panel(
            f"[bold blue]GitForensics Analysis Report[/bold blue] (v{__version__})\n"
            f"Repository: {safe_repository}",
            expand=False,
        )
    )

    status_str = "Complete" if safe_report["is_complete"] else "[bold red]Incomplete[/bold red]"
    meta_str = "Available" if safe_report["github_metadata_available"] else "None (Offline/Local)"

    if not quiet:
        console.print(
            f"Scan Timestamp: {safe_report['scan_timestamp']} | "
            f"Revision: {safe_report['head_commit'] or 'N/A'}\n"
            f"Commits: {safe_report['total_commits']} | "
            f"Contributors: {safe_report['total_contributors']} | "
            f"Tags: {safe_report['total_tags']} | Workflows: {safe_report['total_workflows']}\n"
            f"GitHub API Metadata: {meta_str} | Status: {status_str}"
        )
        console.print("-" * 80)

    risk_score = int(safe_report["risk_score"])
    if risk_score <= 15:
        score_color = "green"
    elif risk_score <= 65:
        score_color = "yellow"
    else:
        score_color = "red"

    console.print(
        f"Overall Assessment: [bold {score_color}]{safe_report['assessment_label']}"
        f"[/bold {score_color}] ([bold]{risk_score}/100[/bold])"
    )
    console.print(f"Transparent Risk Score: [bold yellow]{risk_score}/100[/bold yellow]")

    incomplete_reasons = safe_report["incomplete_analysis_reasons"]
    if isinstance(incomplete_reasons, list) and incomplete_reasons:
        console.print("\n[bold yellow]Warnings / Incomplete Analysis Reasons:[/bold yellow]")
        for reason in incomplete_reasons:
            console.print(f"  - {escape(str(reason))}")

    if quiet:
        return console.export_text()

    safe_findings = safe_report["findings"]
    if not isinstance(safe_findings, list) or not safe_findings:
        console.print("\n[bold green]No findings reported.[/bold green]")
    else:
        table = Table(title="Findings Summary", show_header=True, header_style="bold magenta")
        table.add_column("Rule ID", style="cyan", width=8)
        table.add_column("Severity", width=10)
        table.add_column("Confidence", width=10)
        table.add_column("Title & Evidence", style="white")

        for finding in safe_findings:
            if not isinstance(finding, dict):
                continue
            severity_value = str(finding.get("severity", "INFO"))
            try:
                severity = Severity(severity_value)
            except ValueError:
                severity = Severity.INFO
            sev_style = SEVERITY_COLORS.get(severity, "white")
            sev_badge = f"[{sev_style}]{severity_value}[/{sev_style}]"

            ev_str = ""
            evidence = finding.get("evidence")
            evidence_dict = evidence if isinstance(evidence, dict) else {}
            if verbose:
                ev_items = [
                    f"{escape(str(key))}={escape(str(value))}"
                    for key, value in evidence_dict.items()
                ]
                ev_str = f"\n  [dim]Evidence: {', '.join(ev_items)}[/dim]"
            else:
                rep_hash = (
                    evidence_dict.get("commit_hash")
                    or evidence_dict.get("target_hash")
                    or evidence_dict.get("workflow_path")
                )
                if rep_hash:
                    ev_str = f" ({escape(str(rep_hash))})"

            title_col = (
                f"[bold]{escape(str(finding.get('title', '')))}[/bold]{ev_str}\n"
                f"[dim]{escape(str(finding.get('description', '')))}[/dim]"
            )
            table.add_row(
                escape(str(finding.get("rule_id", ""))),
                sev_badge,
                str(finding.get("confidence", "")),
                title_col,
            )

        console.print(table)

    score_explanation = safe_report["score_explanation"]
    if verbose and isinstance(score_explanation, dict) and score_explanation:
        console.print("\n[bold]Scoring Contribution Breakdown:[/bold]")
        formula = score_explanation.get("formula", "")
        console.print(f"Formula: {escape(str(formula))}")
        caps = score_explanation.get("applied_groupings_and_caps", [])
        if caps:
            console.print("Applied Caps & Groupings:")
            for cap in caps:
                console.print(f"  - {escape(str(cap))}")

    skipped_detectors = safe_report["skipped_detectors"]
    if isinstance(skipped_detectors, list) and skipped_detectors:
        skipped = ", ".join(escape(str(item)) for item in skipped_detectors)
        console.print(f"\n[dim]Skipped Checks ({len(skipped_detectors)}): {skipped}[/dim]")

    console.print(
        "\n[dim]Disclaimer: GitForensics reports observable anomalies and evidence. "
        "It does not declare repository maliciousness.[/dim]"
    )

    return console.export_text()


def _is_pid_running(pid: int) -> bool:
    """Returns True if a process with the given PID is currently running."""
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        process_query_limited_information = 0x1000
        error_invalid_parameter = 87
        still_active = 259
        win_dll = cast(Callable[..., Any], ctypes.__dict__["WinDLL"])
        get_last_error = cast(Callable[[], int], ctypes.__dict__["get_last_error"])
        kernel32 = win_dll("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            return get_last_error() != error_invalid_parameter
        try:
            exit_code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return True
            return exit_code.value == still_active
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except (PermissionError, OSError):
        return True


def _acquire_reservation_lock(lock_path: Path) -> int:
    """Acquires an exclusive Same-Path lock file. Handles stale lock recovery safely."""
    lock_flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW

    import time

    lock_metadata = json.dumps({"pid": os.getpid(), "created_at": time.time()}).encode("utf-8")

    for attempt in range(2):
        try:
            fd = os.open(lock_path, lock_flags, 0o600)
            try:
                os.write(fd, lock_metadata)
                os.fsync(fd)
            except Exception:
                os.close(fd)
                try:
                    os.remove(lock_path)
                except OSError:
                    pass
                raise
            return fd
        except (FileExistsError, OSError) as err:
            if attempt > 0 or not lock_path.exists():
                break

            if os.path.islink(lock_path):
                raise OutputWriteError(
                    f"Report reservation file '{lock_path.name}' is a symbolic link. "
                    f"Manual removal required after verifying process safety."
                ) from err

            try:
                with open(lock_path, encoding="utf-8") as f:
                    content = f.read(4096)
                data = json.loads(content)
                if not isinstance(data, dict):
                    raise ValueError("Lock metadata is not a dictionary.")
                pid = data.get("pid")
                if not isinstance(pid, int) or pid <= 0:
                    raise ValueError("Invalid PID in lock metadata.")
            except Exception:
                raise OutputWriteError(
                    f"Report reservation file '{lock_path.name}' is malformed or unreadable. "
                    f"Manual removal of '{lock_path}' is required after verifying safety."
                ) from err

            if _is_pid_running(pid):
                raise OutputWriteError(
                    f"Output path is reserved by an active process (PID {pid}). "
                    "If the process crashed, verify no gitforensics instance is running "
                    f"and remove '{lock_path}'."
                ) from err

            try:
                os.remove(lock_path)
            except OSError as remove_err:
                raise OutputWriteError(
                    f"Failed to clear stale report reservation file '{lock_path.name}': "
                    f"{remove_err}"
                ) from remove_err

    raise OutputWriteError(
        f"Could not acquire report reservation for '{lock_path.name}'. "
        f"Verify no other process is writing to this path and remove '{lock_path}' if stale."
    )


def write_report_to_file(content: str, output_path: str, force: bool = False) -> None:
    """Safely writes report content to output_path using atomic replacement."""
    try:
        path = safe_output_path(output_path)
    except (OSError, ValueError) as err:
        raise OutputWriteError(sanitize_text(str(err), max_chars=500)) from err

    if not path.parent.exists():
        raise OutputWriteError(f"Parent directory does not exist for output path: '{output_path}'")

    lock_path = path.with_name(f".{path.name}.gitforensics.lock")
    lock_fd: int | None = None
    tmp_file_path: str | None = None
    try:
        lock_fd = _acquire_reservation_lock(lock_path)
        if path.exists() and not force:
            raise CLIArgumentError(
                f"Output file already exists: '{output_path}'. Use --force to overwrite."
            )
        tmp_fd, tmp_file_path = tempfile.mkstemp(
            prefix=".gitforensics_report_", dir=str(path.parent)
        )
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_file_path, path)
    except CLIArgumentError:
        raise
    except OutputWriteError:
        raise
    except Exception as err:
        if tmp_file_path is not None and os.path.exists(tmp_file_path):
            try:
                os.remove(tmp_file_path)
            except OSError:
                pass
        safe_error = sanitize_text(str(err), max_chars=500)
        raise OutputWriteError(f"Failed to write report file safely: {safe_error}") from err
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
            try:
                os.remove(lock_path)
            except OSError:
                pass
