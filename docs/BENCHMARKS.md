# GitForensics Benchmarks

The benchmark uses only deterministic synthetic data and temporary local Git repositories.
It makes no network requests and adds no benchmark dependency. Run it from the repository root:

```text
python benchmarks/performance_benchmark.py --profile full
```

The full profile measures:

- immutable shared-summary construction for 1, 100, 1,000, 10,000, and the configured 50,000
  commit boundary;
- all GF001-GF016 detectors over 10,000 synthetic commit models;
- GF002 with 10,000 unique intervals and GF009 with 10,000 tags;
- 2,000 releases containing 5,000 assets, with all network verification disabled;
- scoring 2,000 findings and JSON report serialization at the configured evidence bounds; and
- extraction from temporary real Git repositories containing 1, 100, and 1,000 commits.

For a shorter development comparison that omits the real 1,000-commit extraction, use:

```text
python benchmarks/performance_benchmark.py --profile standard
```

Each result includes wall-clock duration and peak Python memory measured with `tracemalloc`. The
memory value excludes allocations inside Git subprocesses. Timings are suitable for comparisons on
the same machine and software environment; they are not universal performance guarantees. The
datasets, timestamps, identities, limits, and ordering are fixed so future changes can be compared
against the same workloads. The optional output file is a local measurement artifact and should not
be treated as a portable performance baseline.
