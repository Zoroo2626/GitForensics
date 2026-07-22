"""Typer CLI interface for GitForensics."""

import sys
from types import MappingProxyType

import typer
from rich.console import Console
from rich.markup import escape

from gitforensics import __version__
from gitforensics.engine import run_analysis
from gitforensics.errors import (
    CLIArgumentError,
    GitForensicsError,
    ThresholdBreachedError,
)
from gitforensics.git import parse_repository_input
from gitforensics.models import FailOnLevel, OutputFormat, Severity
from gitforensics.release_models import AssetVerificationConfig
from gitforensics.reporting import render_report, write_report_to_file
from gitforensics.security import SecurityLimits, sanitize_path, sanitize_text

app = typer.Typer(
    name="gitforensics",
    help="GitForensics: Forensic analysis CLI for Git repository history.",
    add_completion=False,
)

console = Console()
err_console = Console(stderr=True)

FAIL_ON_SEVERITY_ORDER = MappingProxyType(
    {
        FailOnLevel.NONE: 99,
        FailOnLevel.CRITICAL: 0,
        FailOnLevel.HIGH: 1,
        FailOnLevel.MEDIUM: 2,
        FailOnLevel.LOW: 3,
    }
)

SEVERITY_RANK = MappingProxyType(
    {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
)


def version_callback(value: bool) -> None:
    if value:
        console.print(f"gitforensics version {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """GitForensics CLI callback."""
    pass


@app.command(name="scan")
def scan(
    path_or_url: str = typer.Argument(..., help="Local repository path or remote GitHub URL."),
    format: OutputFormat = typer.Option(
        OutputFormat.TERMINAL,
        "--format",
        "-f",
        help="Output format (terminal or json).",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="File path to write report output.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Force overwrite existing output file.",
    ),
    rules: str | None = typer.Option(
        None,
        "--rules",
        "-r",
        help="Comma-separated list of rule IDs to run.",
    ),
    github_token: str | None = typer.Option(
        None,
        "--github-token",
        envvar="GITHUB_TOKEN",
        help="GitHub API token for remote analysis.",
    ),
    github_api_url: str = typer.Option(
        "https://api.github.com",
        "--github-api-url",
        help="Base URL for GitHub REST API.",
    ),
    network_timeout: float = typer.Option(
        10.0,
        "--network-timeout",
        help="Timeout in seconds for network requests.",
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Disable all network-dependent GitHub API analysis.",
    ),
    verify_assets: bool = typer.Option(
        False,
        "--verify-assets",
        help=(
            "Enable bounded streaming download and SHA-256 digest verification "
            "of release assets. Disabled by default. Assets are never executed or extracted."
        ),
    ),
    max_asset_size: int = typer.Option(
        100 * 1024 * 1024,
        "--max-asset-size",
        help="Maximum size in bytes for a single asset download (default: 100 MiB).",
    ),
    max_total_download: int = typer.Option(
        500 * 1024 * 1024,
        "--max-total-download",
        help="Maximum total bytes to download across all assets per scan (default: 500 MiB).",
    ),
    max_commits: int = typer.Option(
        50_000,
        "--max-commits",
        help="Maximum commits to process (default: 50000).",
    ),
    max_tags: int = typer.Option(
        10_000,
        "--max-tags",
        help="Maximum tags to process (default: 10000).",
    ),
    max_refs: int = typer.Option(
        20_000,
        "--max-refs",
        help="Maximum refs included in consistency markers (default: 20000).",
    ),
    max_git_output: int = typer.Option(
        64 * 1024 * 1024,
        "--max-git-output",
        help="Maximum stdout bytes retained from one Git command (default: 64 MiB).",
    ),
    max_git_error_output: int = typer.Option(
        1 * 1024 * 1024,
        "--max-git-error-output",
        help="Maximum stderr bytes retained from one Git command (default: 1 MiB).",
    ),
    max_workflow_size: int = typer.Option(
        500_000,
        "--max-workflow-size",
        help="Maximum bytes per workflow file (default: 500000).",
    ),
    max_workflows: int = typer.Option(
        100,
        "--max-workflows",
        help="Maximum workflow files to inspect (default: 100).",
    ),
    max_api_response: int = typer.Option(
        8 * 1024 * 1024,
        "--max-api-response",
        help="Maximum decoded bytes per GitHub API response (default: 8 MiB).",
    ),
    max_api_pages: int = typer.Option(
        20,
        "--max-api-pages",
        help="Maximum GitHub API pages per collection (default: 20).",
    ),
    max_releases: int = typer.Option(
        2_000,
        "--max-releases",
        help="Maximum releases to process (default: 2000).",
    ),
    max_release_assets: int = typer.Option(
        5_000,
        "--max-release-assets",
        help="Maximum release assets to process across a scan (default: 5000).",
    ),
    max_attestation_payload: int = typer.Option(
        1 * 1024 * 1024,
        "--max-attestation-payload",
        help="Maximum decoded bytes per attestation payload (default: 1 MiB).",
    ),
    max_findings: int = typer.Option(
        2_000,
        "--max-findings",
        help="Maximum findings retained in a report (default: 2000).",
    ),
    max_evidence_length: int = typer.Option(
        512,
        "--max-evidence-length",
        help="Maximum characters retained per evidence string (default: 512).",
    ),
    max_evidence_items: int = typer.Option(
        50,
        "--max-evidence-items",
        help="Maximum entries retained in one evidence collection (default: 50).",
    ),
    max_metadata_length: int = typer.Option(
        16_384,
        "--max-metadata-length",
        help="Maximum characters retained for bounded metadata (default: 16384).",
    ),
    max_diff_entries: int = typer.Option(
        1_000_000,
        "--max-diff-entries",
        help="Maximum commit-stat records processed (default: 1000000).",
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable color in terminal output.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Display only final assessment and essential errors.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Enable detailed logging output and expanded evidence.",
    ),
    fail_on: FailOnLevel = typer.Option(
        FailOnLevel.NONE,
        "--fail-on",
        help="Exit with code 5 if any finding meets or exceeds specified severity.",
    ),
) -> None:
    """Scan a repository for history anomalies and potentially manufactured activity."""
    if quiet and verbose:
        err_console.print("[bold red]Error:[/bold red] Cannot specify both --quiet and --verbose.")
        raise typer.Exit(code=2)

    try:
        asset_cfg = AssetVerificationConfig(
            max_asset_size_bytes=max_asset_size,
            max_total_download_bytes=max_total_download,
        )
        asset_cfg.validate()
        security_limits = SecurityLimits(
            max_commits=max_commits,
            max_tags=max_tags,
            max_refs=max_refs,
            max_git_stdout_bytes=max_git_output,
            max_git_stderr_bytes=max_git_error_output,
            max_workflow_file_bytes=max_workflow_size,
            max_workflow_files=max_workflows,
            max_api_response_bytes=max_api_response,
            max_api_pages=max_api_pages,
            max_releases=max_releases,
            max_release_assets=max_release_assets,
            max_attestation_payload_bytes=max_attestation_payload,
            max_findings=max_findings,
            max_evidence_string_chars=max_evidence_length,
            max_evidence_items=max_evidence_items,
            max_metadata_chars=max_metadata_length,
            max_diff_entries=max_diff_entries,
        )
        security_limits.validate()

        repo_input = parse_repository_input(path_or_url)
        report, context = run_analysis(
            repo_input,
            rules_filter=rules.split(",") if rules else None,
            github_token=github_token if not offline else None,
            offline=offline,
            github_api_url=github_api_url,
            verify_assets=verify_assets,
            asset_config=asset_cfg,
            network_timeout=network_timeout,
            security_limits=security_limits,
        )

        if not quiet and format != OutputFormat.JSON:
            console.print(
                f"[bold green]Target Extracted:[/bold green] "
                f"{escape(sanitize_path(context.history.repository_path))}\n"
                f"  - Git Directory: {escape(sanitize_path(context.history.git_dir))} "
                f"(Bare: {context.history.is_bare})\n"
                f"  - HEAD: "
                f"{escape(sanitize_text(context.history.head_commit or 'None (Empty)'))}\n"
                f"  - Total Commits Extracted: {len(context.history.commits)}"
            )

        rendered = render_report(
            report,
            output_format=format,
            no_color=no_color,
            quiet=quiet,
            verbose=verbose,
        )

        if output:
            write_report_to_file(rendered, output, force=force)
            if not quiet and format != OutputFormat.JSON:
                err_console.print(
                    f"[bold green]Report written to:[/bold green] {escape(sanitize_path(output))}"
                )
        else:
            if format == OutputFormat.JSON:
                sys.stdout.write(rendered + "\n")
                sys.stdout.flush()
            else:
                sys.stdout.write(rendered)
                sys.stdout.flush()

        # Check --fail-on threshold
        if fail_on != FailOnLevel.NONE and report.findings:
            target_rank = FAIL_ON_SEVERITY_ORDER[fail_on]
            highest_finding_rank = min(SEVERITY_RANK.get(f.severity, 99) for f in report.findings)
            if highest_finding_rank <= target_rank:
                raise ThresholdBreachedError(
                    f"Findings breached specified --fail-on threshold '{fail_on.value}'."
                )

    except ValueError as err:
        safe_error = sanitize_text(str(err), secrets=(github_token,))
        wrapped = CLIArgumentError(safe_error)
        err_console.print(f"[bold red]Error:[/bold red] {escape(safe_error)}")
        raise typer.Exit(code=wrapped.exit_code) from err
    except GitForensicsError as err:
        safe_error = sanitize_text(str(err), secrets=(github_token,))
        err_console.print(f"[bold red]Error:[/bold red] {escape(safe_error)}")
        raise typer.Exit(code=err.exit_code) from err


def main() -> None:
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()
