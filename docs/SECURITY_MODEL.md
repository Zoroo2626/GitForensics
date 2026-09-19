# GitForensics Security Model

This document describes the security model, trust boundaries, defense mechanisms, and operational constraints implemented in GitForensics.

## Trust Boundaries

GitForensics treats input repository directories, remote repositories, workflow files, and API payloads as untrusted data.

### Untrusted Inputs

* Local filesystem repository paths (may contain hostile `.git` configurations, hooks, or malformed object structures).
* Remote Git repository object stores and metadata.
* `.github/workflows/*.yml` files.
* GitHub REST API response bodies and HTTP headers.
* Downloaded release asset bytes (when `--verify-assets` is enabled).

### Trusted Components

* GitForensics Python package codebase and standard library.
* System `git` binary executable.
* Host operating system process isolation.

## Security Controls and Protections

### 1. Zero Code Execution

GitForensics operates strictly via static analysis of Git metadata and static file content.

* GitForensics never executes code, scripts, binaries, or installers from target repositories.
* GitForensics never imports Python modules from analyzed repositories.
* GitForensics never runs build tools, package managers, or setup scripts.
* Workflow YAML files are inspected as static text; no YAML parser or executable loader is invoked.

### 2. Hostile Subprocess Isolation

All calls to system `git` binaries execute through `subprocess.Popen` wrappers with strict safety flags:

* `shell=False` is enforced on all subprocess invocations with explicit argument lists.
* `--no-pager`, `--no-replace-objects`, and `-c core.hooksPath=/dev/null` are injected into every `git` command to disable interactive pagers, replacement objects, and repository hook scripts.
* Environment variables are sanitized. Inherited `GIT_*` environment variables are stripped, and `GIT_TERMINAL_PROMPT=0` and `GIT_ASKPASS=echo` are enforced to prevent interactive authentication prompts.
* Custom Git configuration options disable external diff tools (`diff.trustExitCode=false`), file system monitors (`core.fsmonitor=false`), mailmaps (`log.mailmap=false`), and credential helpers (`credential.helper=`).

### 3. Disabled Signature Verification Helpers

Git log formatting uses `%H%x00%P%x00...` format strings without `%G?`.

* Traditional Git signature formatters (`%G?`, `%GS`) can trigger external GPG or SSH helper programs configured in the target repository's `.git/config`.
* GitForensics disables signature helper execution entirely.
* Extracted commits and tags have unknown signature status. GF007 reports unavailable coverage and an unknown count instead of treating uninspected commits as unsigned. Signature presence and validity are not inspected.

### 4. Bounded Resource Ceilings

To prevent denial of service from pathological repositories, GitForensics enforces configurable `SecurityLimits`:

* **Git Output Ceiling**: `subprocess.Popen` stdout and stderr streams are read via bounded pipe drainers. Subprocesses exceeding byte limits (default 64 MiB stdout, 1 MiB stderr) are terminated immediately with a typed error.
* **Commit Ceiling**: History extraction is limited to `--max-commits` (default 50,000 commits).
* **Tag Ceiling**: Tag enumeration is bounded to `--max-tags` (default 10,000 tags).
* **Workflow Ceilings**: Local workflow inspections enforce `--max-workflow-size` (default 512 KiB per file) and `--max-workflows` (default 100 files). Symbolic links pointing outside repository root are rejected.
* **API Ceiling**: GitHub API HTTP response streams enforce `--max-api-response` (default 8 MiB per response) and `--max-api-pages` (default 20 pages).

### 5. Repository Mutation Detection

Local repository analysis captures immutable state markers (`RepositoryStateMarker`) before and after extraction:

* State markers capture resolved HEAD, bounded reference digests, Git directory filesystem identity, bare status, and workflow file mtimes/sizes.
* Markers are compared at scan completion without locking or altering repository files.
* If repository HEAD or workflow files change during extraction, GitForensics records a repository mutation warning and marks analysis incomplete.

### 6. Network Restrictions and Origin Validation

* Network requests are disabled entirely when `--offline` is specified. Remote inputs are rejected before extraction, and Git transports and lazy fetches are disabled for local scans.
* GitHub REST API calls are restricted to the approved `api.github.com` HTTPS origin. HTTP redirects to non-approved origins are rejected.
* Workflow files are downloaded with a separate unauthenticated HTTP client and cookie jar. Authenticated API client state is never reused across origins.
* Asset digest verification (`--verify-assets`) streams bytes directly into SHA-256 hashers without storing files on disk. Downloads are restricted to an approved host allowlist (`objects.githubusercontent.com`, `github.com`, `api.github.com`).
* Attestation repository identities must match the expected GitHub repository URL exactly after case folding and optional trailing slash removal. Substring matches are rejected.
* Authentication tokens are passed via headers and are redacted recursively from all exception messages, logs, JSON outputs, and terminal displays.

### 7. Atomic Output Replacement and Same-Path Lock Reservation

Writing scan reports to disk (`--output`) enforces atomic file replacement:

* Before writing, GitForensics acquires an exclusive same-path lock reservation (`.filename.gitforensics.lock`) using `O_CREAT | O_EXCL` flags.
* Lock file metadata includes process ID and creation timestamp. Stale lock files left by dead processes are recovered safely only when PID non-existence is confirmed.
* PID liveness checks use a read-only Windows process handle query or the POSIX signal-zero probe. They never send a terminating signal on Windows.
* Reports are written to a hidden temporary file in the destination directory, flushed and synced (`fsync`), and atomically moved into place using `os.replace`.
* Output paths resolving to existing symbolic links are rejected to prevent symlink overwrite attacks.

## Remaining Security Limitations

* **Subprocess Traversal Overhead**: Pathological Git object databases can consume CPU time during Git binary log generation before output ceilings are reached.
* **Concurrent Local Filesystem Mutations**: State markers detect modifications occurring between scan start and end, but local scans do not freeze filesystem state.
* **Metadata-Only Attestation Inspection**: GitHub release attestation analysis parses API metadata fields only; cryptographic proof validation is not performed.
* **Unknown Commit Signatures**: Signature presence and validity are not inspected. Unknown status is distinct from unsigned; signature coverage is unavailable when any commit has unknown status.
