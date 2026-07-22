# GitForensics CLI Usage Guide

This guide provides detailed usage instructions and examples for the GitForensics command-line interface.

## Command Overview

The main entry point for GitForensics is `gitforensics`.

```bash
gitforensics [OPTIONS] COMMAND [ARGS]...
```

### Global Options

* `--version`, `-v`: Display package version and exit.
* `--help`: Display CLI help text and exit.

## The `scan` Command

The `scan` command extracts and analyzes repository history from a local directory path or remote GitHub URL.

```bash
gitforensics scan <path-or-url> [OPTIONS]
```

### Input Targets

* Local directory path: `gitforensics scan /path/to/repo`
* Local current directory: `gitforensics scan .`
* Remote GitHub HTTPS URL: `gitforensics scan https://github.com/owner/repo`
* Remote GitHub SSH URL: `gitforensics scan git@github.com:owner/repo.git`
* GitHub shorthand: `gitforensics scan owner/repo`

### Output Options

#### `--format`, `-f`

Select the output format (`terminal` or `json`). Default is `terminal`.

```bash
gitforensics scan . --format json
```

#### `--output`, `-o`

Write the report to a specified file path instead of stdout.

```bash
gitforensics scan . --output report.txt
```

#### `--force`

Force overwriting an existing report file. Without `--force`, existing files generate exit code 2.

```bash
gitforensics scan . --output report.txt --force
```

#### `--quiet`, `-q`

Display only essential output (assessment label, numeric score, and warnings).

```bash
gitforensics scan . --quiet
```

#### `--verbose`

Display expanded evidence key-value pairs, scoring formula breakdowns, and detailed log messages.

```bash
gitforensics scan . --verbose
```

#### `--no-color`

Disable ANSI color codes and Rich markup formatting in terminal output.

```bash
gitforensics scan . --no-color
```

### Selective Rule Execution

#### `--rules`, `-r`

Specify a comma-separated list of rule IDs to execute. Unlisted rules are skipped.

```bash
gitforensics scan . --rules GF001,GF005,GF006
```

### Remote API and Network Options

#### `--github-token`

Provide a GitHub REST API token. Prefer the `GITHUB_TOKEN` environment variable so the token does
not appear in shell history.

```bash
GITHUB_TOKEN="TOKEN_VALUE" gitforensics scan owner/repo
```

#### `--github-api-url`

Base URL for GitHub REST API calls. Default is `https://api.github.com`.

```bash
gitforensics scan owner/repo --github-api-url https://api.github.com
```

#### `--network-timeout`

Network timeout in seconds for HTTP API requests. Default is `10.0`.

```bash
gitforensics scan owner/repo --network-timeout 15.0
```

#### `--offline`

Disable all network-dependent GitHub API requests. Local Git history detectors execute normally.

```bash
gitforensics scan owner/repo --offline
```

#### `--verify-assets`

Enable bounded streaming SHA-256 digest calculation for GitHub release assets. Disabled by default.

```bash
gitforensics scan owner/repo --verify-assets
```

### Severity Threshold Exit Control

#### `--fail-on`

Exit with code 5 if any detected finding meets or exceeds the specified severity level (`none`, `low`, `medium`, `high`, `critical`). Default is `none`.

```bash
gitforensics scan . --fail-on high
```

## Output Formats

### Terminal Output Structure

The terminal output includes:

1. **Header Panel**: Repository target, GitForensics version.
2. **Metadata Summary**: Scan timestamp, HEAD commit hash, commit count, contributor count, tag count, workflow count, GitHub API status, completeness status.
3. **Assessment Summary**: Overall assessment label, numeric risk score (0-100).
4. **Warnings Block**: Displays reasons if analysis was incomplete or repository mutation was detected.
5. **Findings Table**: Displays Rule ID, Severity badge, Confidence, Title, Description, and Evidence summary.
6. **Scoring Breakdown**: Formula details (visible in `--verbose` mode).
7. **Skipped Checks**: List of detector rule IDs skipped during analysis.
8. **Disclaimer**: Reminder that findings reflect metadata evidence and do not declare malicious intent.

### JSON Output Schema

When `--format json` is selected, standard JSON (schema version `1.0.0`) is emitted:

```json
{
  "schema_version": "1.0.0",
  "repository": ".",
  "input_type": "local",
  "scan_timestamp": "2026-07-22T19:00:00Z",
  "duration_seconds": 0.42,
  "head_commit": "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4",
  "total_commits": 150,
  "total_contributors": 3,
  "total_tags": 2,
  "total_workflows": 1,
  "github_metadata_available": false,
  "total_releases": 0,
  "release_analysis": null,
  "is_complete": true,
  "incomplete_analysis_reasons": [],
  "risk_score": 15,
  "assessment_label": "Low observed concern",
  "score_explanation": {
    "score": 15,
    "assessment_label": "Low observed concern",
    "base_score": 15,
    "formula": "Score = MIN(100, SUM(Capped_Groups) + SUM(Individual_Weighted_Findings))",
    "finding_contributions": [],
    "applied_groupings_and_caps": [],
    "excluded_findings": [],
    "max_possible_score": 100,
    "scoring_model_version": "1.0.0"
  },
  "findings": [],
  "skipped_detectors": [
    "GF008",
    "GF010",
    "GF011",
    "GF012",
    "GF013",
    "GF014",
    "GF015",
    "GF016"
  ],
  "failed_detectors": []
}
```
