# Performance and resource gates

TrustWeave processes only **explicitly supplied local declarations and artifacts**. Its scale checks measure bounded deterministic operations; they do not connect to services, execute agents or tools, or inspect a deployed environment.

## Purpose

The regression suite exercises representative declaration sizes and graph shapes so that changes which introduce accidental super-linear behavior, unbounded path enumeration, or unexpectedly large local artifacts are detected before release. These are intentionally broad CI guards rather than microbenchmarks: they protect a practical ceiling while tolerating normal differences between supported operating systems and Python versions.

| Workload | Deterministic assertion | CI budget |
| --- | --- | --- |
| Declared flows | Evaluate 10, 1,000, and 50,000 flows using one declared rule | 50,000 flows complete in less than 15 seconds |
| Policy rules | Evaluate first-match decisions across 10 and 1,000 ordered rules | Each decision completes in less than 5 seconds |
| Chain graphs | Traverse dense diamond and cyclic declarations with explicit path, state, and edge budgets | Review completes in less than 10 seconds and never exceeds `max_paths` |
| SARIF conversion | Convert 5,000 locally supplied risk findings | Conversion completes in less than 15 seconds; serialized SARIF remains below 10 MiB |

These budgets are release safeguards, not service-level objectives. They are deliberately conservative because supported environments vary in CPU capacity and because TrustWeave is a local command-line evidence tool.

## Bounded analysis

Chain analysis applies its path, state, edge, and depth limits **before** the corresponding counter is incremented. When a supplied graph reaches a configured limit, TrustWeave returns deterministic partial evidence and a `TW-CHAIN-004` finding rather than claiming complete analysis. The performance tests include a dense diamond graph with a cycle to retain this guarantee under a shape that would otherwise multiply paths.

Input loading is also bounded. Local JSON or safe YAML documents reject symbolic links, invalid UTF-8, oversized byte streams, recursive or aliased structures, excessive nesting, non-string object keys, and excessive item counts. These limits make resource consumption explicit while preserving the product boundary: declarations are reviewed as data and are never executed.

## Reproducing the gates

Run the performance gates directly with:

```shell
pytest tests/test_performance.py -q --no-cov
```

Run the complete release-quality suite with:

```shell
ruff format --check .
ruff check .
mypy src
bandit -r src/trustweave -q
pytest
python scripts/reality_check.py
```

A performance failure should be investigated with the same supplied fixture shape. Do not weaken a budget solely to accommodate a regression. If a deliberate compatibility or capability change requires a new ceiling, update the test and this document together, explain the reason in the changelog, and retain a bounded limit.
