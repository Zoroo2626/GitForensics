# GitForensics

GitForensics is a local-first Python CLI tool that analyzes Git repository history and reports evidence of unusual or potentially manufactured repository activity.

## Overview

Software source repositories can contain altered commit histories, artificial activity patterns, or disconnected release artifacts. Security reviews and open-source evaluations often require inspecting repository metadata to identify anomalies before relying on repository history.

GitForensics performs static analysis on Git commit metadata, tags, workflow files, and optional GitHub release metadata. It executes locally, parses machine-readable Git output, and generates structured reports detailing observable anomalies.

### Analysis Scope

GitForensics analyzes the following repository components:

* Commit timestamps, ordering, and interval distributions
* Author and committer identities across history
* Single-commit import volumes and contributor concentration ratios
* Repository tags and object references
* GitHub Actions workflow files for history-modifying commands
* GitHub repository metadata and creation timestamps when accessible
* GitHub release metadata, tag mappings, inter-release commit deltas, and asset digests

### Important Disclaimers

GitForensics reports observable anomalies and evidence based on factual repository metadata.

* GitForensics does not claim or prove that a repository is malicious, safe, genuine, or trustworthy.
* GitForensics does not perform static code analysis or malware detection on repository files.
* Findings reflect metadata anomalies and require human review in context.

## Installation

GitForensics requires Python 3.10 or newer and a local `git` executable on system PATH.

### Installing from Source

```bash
git clone https://github.com/GitForensics/GitForensics.git
cd GitForensics
python -m pip install .
```

### Installing from a Built Wheel

```bash
python -m pip install dist/gitforensics-0.1.0-py3-none-any.whl
```

### Verification

Confirm that the installation succeeded:

```bash
gitforensics --version
gitforensics --help
```

## Basic Usage

The primary command is `gitforensics scan`:

```bash
gitforensics scan <path-or-url> [OPTIONS]
```

### Scanning a Local Repository

Scan a directory on the local filesystem:

```bash
gitforensics scan /path/to/local/repository
```

Scan the current working directory:

```bash
gitforensics scan .
```

### Scanning a Remote GitHub Repository

Scan a GitHub repository by URL:

```bash
gitforensics scan https://github.com/owner/repository
```

Scan using GitHub shorthand format:

```bash
gitforensics scan owner/repository
```

### Offline Mode

Disable all network requests to GitHub API endpoints:

```bash
gitforensics scan /path/to/repository --offline
```

### Writing Report Output to a File

Write the report to a destination file:

```bash
gitforensics scan . --output report.txt
```

Overwrite an existing report file:

```bash
gitforensics scan . --output report.txt --force
```

### Generating JSON Output

Output structured JSON to standard output:

```bash
gitforensics scan . --format json
```

Save structured JSON to a file:

```bash
gitforensics scan . --format json --output report.json
```

### Bounded Asset Digest Verification

Optionally verify release asset SHA-256 digests via streaming HTTP requests without downloading full files into memory or executing them:

```bash
gitforensics scan owner/repository --verify-assets
```

Asset verification is disabled by default.

## Security and Resource Limit Options

GitForensics enforces default resource ceilings to ensure bounded execution when analyzing untrusted repositories.

| Option | Default | Description |
|---|---|---|
| `--max-commits` | 50000 | Maximum commits to extract and analyze |
| `--max-tags` | 10000 | Maximum tags to parse from repository |
| `--max-git-output` | 67108864 | Maximum stdout bytes from Git commands (64 MiB) |
| `--max-workflow-size` | 500000 | Maximum size in bytes per workflow file (500 KB) |
| `--max-workflows` | 100 | Maximum local workflow files to inspect |
| `--max-api-response` | 8388608 | Maximum response bytes from GitHub API endpoints (8 MiB) |
| `--max-api-pages` | 20 | Maximum API pagination requests per collection |
| `--max-releases` | 2000 | Maximum GitHub releases to process |
| `--max-release-assets` | 5000 | Maximum release assets to process across a scan |
| `--max-asset-size` | 104857600 | Maximum size in bytes for a single verified asset (100 MiB) |
| `--max-total-download` | 524288000 | Maximum cumulative download bytes across asset verification (500 MiB) |
| `--max-findings` | 2000 | Maximum findings retained in a report |
| `--max-evidence-length` | 512 | Maximum character length per evidence string |
| `--max-evidence-items` | 50 | Maximum items per evidence collection |
| `--max-metadata-length` | 16384 | Maximum character length for metadata strings |
| `--max-diff-entries` | 1000000 | Maximum commit stat records processed |

## Exit Codes

GitForensics uses standard exit codes to indicate execution results:

* `0`: Scan completed successfully without breaching configured `--fail-on` threshold.
* `1`: General runtime or internal analysis error.
* `2`: Invalid CLI arguments, option conflict, or output path write failure.
* `3`: Invalid Git repository path, inaccessible directory, or Git command failure.
* `4`: GitHub API network failure during remote analysis.
* `5`: Severity threshold breached when using `--fail-on`.

### Threshold Failure Example

Exit with code 5 if any finding reaches `HIGH` or `CRITICAL` severity:

```bash
gitforensics scan . --fail-on high
```

## Rule Index

GitForensics includes 16 deterministic detectors:

| Rule ID | Name | Severity | Description |
|---|---|---|---|
| `GF001` | Initial import concentration | HIGH / MEDIUM | High proportion of codebase lines added in single initial commit |
| `GF002` | Mechanically regular intervals | MEDIUM | Commits spaced at exact, programmatic time intervals |
| `GF003` | Unusual commit bursts | MEDIUM | Unrealistic commit frequency within a short time window |
| `GF004` | Contributor concentration | LOW | Single author identity responsible for all commits across a long lifespan |
| `GF005` | Identity mismatches | HIGH / MEDIUM | Discrepancies between author and committer names or emails |
| `GF006` | Timestamp ordering anomalies | HIGH / CRITICAL | Child commit timestamp precedes its parent commit timestamp |
| `GF007` | Commit signature coverage | INFO | Low ratio of signed commits across repository history |
| `GF008` | History-modifying workflows | HIGH / CRITICAL | Workflow files containing force push or history alteration commands |
| `GF009` | Tag anomalies | HIGH / MEDIUM | Tags referencing missing objects or created in sudden bulk bursts |
| `GF010` | Repository age discrepancy | HIGH / MEDIUM | GitHub repository creation date significantly later than earliest commit |
| `GF011` | Unresolvable release revision | MEDIUM / LOW | Release tag or target commitish does not resolve to analyzed history |
| `GF012` | Repeated release targets | MEDIUM | Multiple distinct releases pointing to the exact same commit |
| `GF013` | Release chronology conflict | MEDIUM / LOW | Semver version order conflicts with release publication timestamps |
| `GF014` | Asset-heavy minimal source | LOW / INFO | Heavy binary assets attached to a release with minimal source code changes |
| `GF015` | Mutable release asset | LOW / INFO | Release asset metadata updated substantially after release publication |
| `GF016` | Asset digest and attestation | HIGH / INFO | Asset digest mismatch or attestation repository identity discrepancy |

Refer to [docs/RULES.md](docs/RULES.md) for detailed evidence structures, thresholds, and false-positive context.

## Scoring System

GitForensics calculates a deterministic risk score between 0 and 100 based on weighted findings:

* `CRITICAL`: 30 points
* `HIGH`: 15 points
* `MEDIUM`: 5 points
* `LOW`: 1 point
* `INFO`: 0 points

Score contributions are adjusted by confidence multipliers (`HIGH`: 1.0, `MEDIUM`: 0.7, `LOW`: 0.4) and capped across related rule categories to prevent double counting overlapping signals.

Assessment labels map directly to numeric scores:

* `0 - 15`: Low observed concern
* `16 - 35`: Moderate observed concern
* `36 - 65`: Elevated observed concern
* `66 - 100`: High observed concern

## Analysis Completeness and Mutation Safeguards

### Incomplete Analysis Handling

If a detector or remote API check encounters rate limits, network timeouts, or output ceilings, the scan continues. The report marks `is_complete: false` and logs the exact reason under `incomplete_analysis_reasons`.

### Repository Mutation Safeguards

For local scans, GitForensics captures state markers before and after history extraction. If the local repository HEAD, reference set, or workflows change during the scan, GitForensics records a repository mutation warning and marks the analysis incomplete.

## Security Model

GitForensics applies strict security boundaries when inspecting untrusted repositories:

* Operating via read-only static metadata analysis without executing repository code, scripts, or hooks.
* Executing Git commands with `shell=False` and setting `core.hooksPath=/dev/null`.
* Disabling GPG and SSH signature helper programs during Git extraction to prevent code execution via malicious repository configurations.
* Enforcing process stdout and stderr byte limits on Git subprocesses.
* Enforcing approved HTTPS origin checks on GitHub API requests and redirects.
* Redacting tokens, credentials, and local paths from reports and logs.
* Using atomic file replacement with exclusive same-path lock reservations for report writing.

Refer to [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for detailed trust boundaries and security controls.

## Known Limitations

* Commit signatures are reported conservatively as unverified because external signature verification helpers are disabled for security reasons.
* Remote GitHub API requests are restricted to `api.github.com`. Custom GitHub Enterprise endpoints require manual configuration.
* Local repository state markers detect filesystem modifications during a scan, but local scans do not create a frozen filesystem snapshot.
* Release attestation checks parse API metadata only and do not perform cryptographic signature validation.

## Development Setup

Clone the repository and install development dependencies:

```bash
git clone https://github.com/GitForensics/GitForensics.git
cd GitForensics
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m pip install pytest pytest-cov ruff mypy build
```

### Running Tests

Run the unit test suite:

```bash
python -m pytest
```

Run tests with coverage reporting:

```bash
python -m pytest --cov=gitforensics --cov-report=term-missing
```

Run linter and formatter checks:

```bash
python -m ruff check .
python -m ruff format --check .
```

Run static type checking:

```bash
python -m mypy src
```

Build distribution packages:

```bash
python -m build
```

### Running Benchmarks

Execute the deterministic performance benchmarks:

```bash
python benchmarks/performance_benchmark.py --profile standard
```

Refer to [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for benchmark instructions and performance baselines.

## License

GitForensics is licensed under the MIT License. See [LICENSE](LICENSE) for details.
