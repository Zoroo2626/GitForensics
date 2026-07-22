# GitForensics Detector Rule Index

This document provides a factual description of each anomaly detector rule in GitForensics (GF001 through GF016).

## Local History Detectors (GF001 - GF007, GF009)

### GF001: Initial Import Concentration

* **Title**: Initial import concentration
* **Default Severity**: HIGH (for >90% code added in initial commit) or MEDIUM (>75%)
* **Default Confidence**: HIGH
* **Description**: Detects repositories where a large proportion of total repository lines were added in the very first commit, hiding prior commit history.
* **Evidence**: Initial commit hash, lines inserted in initial commit, total repository lines, insertion percentage.
* **False Positive Context**: Genuine initial open-source releases of established projects or single-file scripts often have 100% of code in the initial commit.

### GF002: Mechanically Regular Commit Intervals

* **Title**: Mechanically regular commit intervals
* **Default Severity**: MEDIUM
* **Default Confidence**: HIGH
* **Description**: Detects commit sequences where consecutive commits are separated by exact, recurring time intervals (e.g. exactly 60 seconds or 300 seconds apart).
* **Evidence**: Dominant interval in seconds, recurring commit sequence count, matching commit hashes.
* **False Positive Context**: Automated bot commits, scheduled CI version bumps, or scripted dependency updates can produce regular commit intervals.

### GF003: Unusual Commit Bursts

* **Title**: Unusual commit bursts
* **Default Severity**: MEDIUM
* **Default Confidence**: MEDIUM
* **Description**: Detects short time windows containing an uncharacteristically high number of commits compared to average repository activity.
* **Evidence**: Burst window start time, end time, commit count in window, average commits per window.
* **False Positive Context**: Automated migrations, mass refactoring scripts, or repository imports can generate legitimate commit bursts.

### GF004: Contributor Concentration

* **Title**: Contributor concentration
* **Default Severity**: LOW
* **Default Confidence**: MEDIUM
* **Description**: Detects repositories spanning a long lifespan and significant commit volume where 100% of commits originate from a single contributor identity.
* **Evidence**: Sole author email, author name, total commits, active history duration in days.
* **False Positive Context**: Solo developer projects and personal utilities naturally have single-contributor history.

### GF005: Author and Committer Identity Mismatches

* **Title**: Author and committer identity mismatches
* **Default Severity**: HIGH (>50% mismatch ratio) or MEDIUM (>20% mismatch ratio)
* **Default Confidence**: HIGH
* **Description**: Detects significant discrepancies between author identities and committer identities across repository commits.
* **Evidence**: Total commits analyzed, mismatched commit count, mismatch percentage, representative author/committer pairs.
* **False Positive Context**: Git patch workflows, rebase operations, cherry-picks, and PR merge queues legitimately result in author/committer identity differences.

### GF006: Timestamp Ordering Anomalies

* **Title**: Timestamp ordering anomalies
* **Default Severity**: HIGH (author/committer date inversion) or CRITICAL (chronological paradox with parent commit)
* **Default Confidence**: HIGH
* **Description**: Detects commits whose timestamps precede their parent commits, or commits where author date postdates committer date by significant margins.
* **Evidence**: Parent commit hash, parent timestamp, child commit hash, child timestamp, time inverted delta in seconds.
* **False Positive Context**: Clock skew on developer machines, offline committing, or manual date overrides during git rebase can create timestamp inversions.

### GF007: Commit Signature Coverage

* **Title**: Commit signature coverage
* **Default Severity**: INFO
* **Default Confidence**: HIGH
* **Description**: Reports the proportion of commits containing GPG or SSH cryptographic signatures. GitForensics treats signatures conservatively as unverified because external signature verification helpers are disabled during extraction.
* **Evidence**: Total commits, signed commit count, unsigned commit count, signature ratio.
* **False Positive Context**: Unsigned commits are standard in many open-source projects.

### GF009: Tag Creation Anomalies

* **Title**: Tag creation anomalies
* **Default Severity**: HIGH (tag pointing to unresolvable object) or MEDIUM (bulk tag creation burst)
* **Default Confidence**: HIGH
* **Description**: Detects tags pointing to non-existent objects or massive clusters of tags created within seconds of each other.
* **Evidence**: Tag name, target hash, tag object status, tag creation timestamp cluster.
* **False Positive Context**: Automated release scripts or version tag backfilling can create multiple tags rapidly.

## Remote and Workflow Detectors (GF008, GF010, GF011 - GF016)

### GF008: History-Modifying Workflows

* **Title**: GitHub Actions workflow containing history-modifying commands
* **Default Severity**: HIGH or CRITICAL
* **Default Confidence**: HIGH
* **Description**: Inspects `.github/workflows/*.yml` files for commands that perform forced pushes (`git push --force`), branch deletions, or filter-repo actions.
* **Evidence**: Workflow file path, step name, matching command string, line number.
* **False Positive Context**: Deployment workflows that push compiled documentation or gh-pages branches often use forced pushes.
* **Detection Limitation**: GF008 uses static, line-oriented patterns. It does not expand shell variables, decode commands, join multi-line shell expressions, or resolve YAML anchors, so deliberately obfuscated commands can evade detection.

### GF010: Repository Age Discrepancy

* **Title**: Repository creation date postdates commit history
* **Default Severity**: HIGH (>365 days gap) or MEDIUM (>30 days gap)
* **Default Confidence**: HIGH
* **Description**: Compares GitHub repository `created_at` timestamp with the earliest commit date in history. Detects repositories created on GitHub long after their history commenced.
* **Evidence**: GitHub creation date, earliest commit date, discrepancy duration in days.
* **False Positive Context**: Migrating existing codebase history from another forge (GitLab, Bitbucket, SVN) to GitHub creates a valid creation gap.

### GF011: Unresolvable Release Revision

* **Title**: Release without resolvable source revision
* **Default Severity**: MEDIUM (or LOW if history extraction was limited)
* **Default Confidence**: MEDIUM (or LOW if history extraction was limited)
* **Description**: Detects GitHub releases whose tag or target commitish cannot be connected to a commit in analyzed Git history.
* **Evidence**: Release ID, release name, tag name, target commitish, resolution failure reason.
* **False Positive Context**: Shallow clones or commit history limits can prevent tag resolution.

### GF012: Repeated Release Targets

* **Title**: Multiple releases targeting the same commit
* **Default Severity**: MEDIUM
* **Default Confidence**: HIGH
* **Description**: Detects 3 or more distinct GitHub releases pointing to the exact same commit hash.
* **Evidence**: Shared target commit hash, release count, list of affected release names, publication window.
* **False Positive Context**: Maintainers occasionally publish separate release channels (e.g., latest, stable, v1) on the same release commit.

### GF013: Release Chronology Conflict

* **Title**: Release version order conflicts with publication order
* **Default Severity**: MEDIUM (if ancestry confirms conflict) or LOW
* **Default Confidence**: HIGH (if ancestry confirms conflict) or MEDIUM
* **Description**: Detects cases where a release with a lower semantic version number was published after a release with a higher version number, and commit ancestry confirms the conflict.
* **Evidence**: Older release version, published timestamp, newer release version, published timestamp, ancestry relationship.
* **False Positive Context**: Maintenance patch releases for older major versions (e.g. publishing v1.2.9 after v2.0.0) are legitimate.

### GF014: Asset-Heavy Minimal Source Release

* **Title**: Asset-heavy release with minimal source change
* **Default Severity**: LOW (or INFO for first release)
* **Default Confidence**: MEDIUM (or LOW for first release)
* **Description**: Detects releases with large binary asset payloads where the commit delta since the previous release contains minimal source file changes.
* **Evidence**: Release name, binary asset count, total asset size in bytes, commits since previous release, file changes since previous release.
* **False Positive Context**: Pre-compiled binary distributions or standalone artifact releases may accompany small bugfix commits.

### GF015: Mutable Release Asset

* **Title**: Release asset updated substantially after publication
* **Default Severity**: LOW (created >1h after pub) or INFO (updated >1h after creation)
* **Default Confidence**: MEDIUM
* **Description**: Identifies release assets whose creation or update timestamps postdate release publication by a substantial time margin.
* **Evidence**: Release name, asset name, publication timestamp, asset creation timestamp, asset update timestamp, time delta in seconds.
* **False Positive Context**: Re-uploading corrupted build artifacts or adding supplementary platform builds later can create asset timestamp gaps.

### GF016: Asset Digest and Attestation Anomaly

* **Title**: Release asset digest mismatch or attestation discrepancy
* **Default Severity**: HIGH (calculated digest mismatch or repository identity mismatch) or INFO (missing server digest)
* **Default Confidence**: HIGH
* **Description**: Reports release assets whose streaming SHA-256 digest differs from server-provided metadata, missing server digests, or attestations whose repository identity differs from the expected repository.
* **Evidence**: Asset name, calculated SHA-256 digest, server digest, attestation repository URI, attestation workflow reference.
* **False Positive Context**: Missing server digests occur on older GitHub releases before API digest indexing was added.
