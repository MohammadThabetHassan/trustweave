# Local Resource Bounds

## Purpose

TrustWeave accepts **local declarations and already-recorded metadata**. This document records the deterministic structural and output bounds implemented to keep that processing reviewable and fail-closed. The limits are local evidence-processing controls; they are not performance guarantees for arbitrary hardware, a live-service quota, or a runtime-security control.

## Input-document bounds

| Boundary | Implemented limit | Failure behavior |
| --- | ---: | --- |
| Local input file size | **16 MiB** (`16 * 1024 * 1024` bytes) | Reject before reading text when `stat().st_size` exceeds the limit. |
| Nested maps/sequences | **64** levels | Reject the parsed local document with a path-aware validation error. |
| Mapping/sequence items | **1,000,000** items | Reject the parsed local document before downstream artifact generation. |
| Input path kind | Regular, non-symlink local file only | Reject symbolic links, missing paths, directories, unreadable files, and invalid UTF-8. |
| YAML behavior | Safe YAML parsing only when JSON parsing fails and optional PyYAML support is installed | Reject unsafe YAML tags, empty content, and non-string object keys. |

The loader checks file size before `read_text`, then validates nesting and item count iteratively rather than relying on unbounded recursive traversal. These controls apply to the package’s local document loader and do not contact a remote source or resolve an external reference.

## Declared-chain bounds

Declared-chain analysis uses the following deterministic default budgets.

| Boundary | Default | Behavior when reached |
| --- | ---: | --- |
| Nodes | 1,000 | Emit bounded local review evidence identifying the exhausted `max_nodes` budget. |
| Paths | 1,000 | Stop adding terminal paths and identify the exhausted `max_paths` budget. |
| Traversed edges | 5,000 | Stop traversal and identify the exhausted `max_edges` budget. |
| Path depth | 100 | Stop traversal and identify the exhausted `max_depth` budget. |
| Explored states | 5,000 | Stop traversal and identify the exhausted `max_states` budget. |

These values constrain declared static metadata propagation. They do not inspect a real agent execution, establish live graph completeness, or guarantee that a separately deployed runtime will obey a declared path.

## Output-evidence bounds

| Boundary | Implemented limit | Failure behavior |
| --- | ---: | --- |
| SARIF unique results | **50,000** | Reject local SARIF export before adding a new unique result beyond the bound. |
| Generated corpus artifacts | Exact reviewed path inventory and canonical digest set | The check-only verifier reports output drift; it never refreshes snapshots automatically. |
| Reproducible staged-CI evidence | Exact ten-file artifact set | The clean-checkout helper rejects path-set or byte differences between two fixed-input local runs. |

The SARIF limit applies to unique result identities after deterministic deduplication. Multiple locations for an existing canonical result remain grouped as one result. The limit prevents unbounded local result materialization; it does not provide a wall-clock service-level objective or prevent an input file below the size ceiling from requiring meaningful local computation.

## Verification

The relevant regression suites cover over-size files, nesting, item counts, symlink refusal, UTF-8/YAML handling, bounded chain traversal, SARIF cardinality, deterministic golden evidence, and clean-checkout reproducibility. Run the project’s full local quality suite for release evidence. The following commands run the two explicit reproducibility checks:

```bash
python scripts/verify_golden_evidence.py
python scripts/verify_release_reproducibility.py \
  --source-revision "$(git rev-parse HEAD)" \
  --generated-at 2026-08-19T00:00:00+00:00
```

> Timing observations are informative only. TrustWeave intentionally does not enforce a fragile hosted-runner wall-clock threshold as part of this resource contract.
