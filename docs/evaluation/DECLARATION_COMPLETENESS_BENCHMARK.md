# Synthetic declaration-consistency benchmark

## Purpose

This prepared benchmark addresses one narrow evaluation question: **when supplied static framework metadata and a supplied TrustWeave manifest agree, differ, or include an explicit maintainer-declared label pairing, can a reviewer reproduce the resulting local evidence artifact?**

It is intentionally a local, deterministic fixture suite. It does not import or execute a framework, inspect application source, read an environment, load a credential, connect to a service, execute a tool, or observe a running agent. It does not prove that either declaration is complete. The benchmark is **not yet an independent evaluation result** and must not be described as a framework-security scan, runtime-completeness check, or measure of vulnerability detection.

## What it compares

Each benchmark case contains two checked-in inputs:

| Input | Meaning | Trust boundary |
| --- | --- | --- |
| Framework descriptor | An already-provided OpenAI Agents-style JSON export containing agent names and static tool labels. | It is review data; its authenticity and completeness are not established. |
| TrustWeave manifest | An explicitly supplied local manifest containing declared tool names. | It is a declaration; it is not a representation proven to match an executable agent. |
| Declared reconciliation | An optional, explicit mapping supplied by the synthetic fixture maintainer. | It is a transparent reviewer-provided label pairing, not automatic matching or verified semantic equivalence. |

The runner normalizes the supplied descriptor with the existing `framework-import` contract and compares **exact tool-label sets** with validated manifest tool names. It always records raw framework-only and manifest-only labels. An optional reconciliation can pair one raw label from each side only when that exact pair is explicitly present in the checked-in fixture. It never removes raw differences.

> Exact label agreement is a bounded consistency signal. A declared reconciliation is a reviewer-visible local assertion. Neither proves source equivalence, runtime reachability, authorization, input authenticity, or security.

## Synthetic cases and fixture metrics

| Case | Fixture condition | Expected local result | Why it exists |
| --- | --- | --- | --- |
| `TW-COMP-001` | Supplied descriptor and manifest use the same three tool labels. | `complete` | Positive exact-label agreement control. |
| `TW-COMP-002` | Supplied descriptor includes `webhook_notify`, absent from the supplied manifest. | `mismatch`; one unresolved framework-only label. | One-sided framework-to-manifest mismatch control. |
| `TW-COMP-003` | Supplied manifest includes `audit_log`, absent from the supplied descriptor. | `mismatch`; one unresolved manifest-only label. | Reverse-direction mismatch control. |
| `TW-COMP-004` | Supplied artifacts have two raw differences in each direction, paired by two explicit fixture mappings. | `declared_reconciliation`; raw differences retained, zero unresolved labels. | Tests transparent reconciliation without hiding the original disagreement. |
| `TW-COMP-005` | Empty framework inventory against single-tool manifest. | `mismatch`; one unresolved manifest-only label. | Tests the empty-inventory edge case. |
| `TW-COMP-006` | Single-tool exact agreement. | `complete` | Confirms comparison works at the smallest non-empty scale. |
| `TW-COMP-007` | Multi-agent overlapping tool deduplication. | `complete` | Confirms deduplication produces the correct unique set. |
| `TW-COMP-008` | Multiple framework-only static tool labels. | `mismatch`; multiple unresolved framework-only labels. | Multi-label framework-only mismatch control. |
| `TW-COMP-009` | Multiple manifest-only static tool labels. | `mismatch`; multiple unresolved manifest-only labels. | Reverse multi-label mismatch control. |
| `TW-COMP-010` | Bidirectional unresolved mismatch without reconciliation. | `mismatch`; unresolved labels on both sides. | Tests that raw differences remain visible. |
| `TW-COMP-011` | Partial reconciliation with remaining unresolved labels. | `mismatch`; unresolved labels remain. | Tests partial reconciliation. |
| `TW-COMP-012` | LangGraph empty tool inventory against single-tool manifest. | `mismatch`; one unresolved manifest-only label. | Tests cross-framework empty inventory mismatch. |
| `TW-COMP-013` | CrewAI complete declared tool surface. | `complete` | Cross-framework positive control. |
| `TW-COMP-014` | CrewAI framework-only mismatch. | `mismatch`; unresolved framework-only label. | Cross-framework mismatch control. |

The summary records only deterministic fixture metrics:

| Metric | Definition | Excluded conclusion |
| --- | --- | --- |
| Exact agreement cases | Cases whose supplied tool-label sets are identical. | That an agent, framework configuration, or source tree is complete. |
| Raw framework-only labels | Tool labels in supplied framework metadata but absent from the supplied manifest. | That a live capability exists, is reachable, or is unsafe. |
| Raw manifest-only labels | Tool names in the supplied manifest but absent from supplied framework metadata. | That the descriptor is stale, malicious, or incomplete. |
| Declared reconciliation cases | Cases whose raw labels were fully paired by an explicit checked-in mapping. | That the paired labels have verified equivalent behavior. |
| Unresolved labels | Raw differences not paired by a declared mapping. | Detection rate, false-positive rate, or security efficacy on real agents. |
| Fixture conformance | Whether observed output equals the checked-in expected output. | User-study, adoption, performance, comparative, or external-validation outcomes. |

These are **benchmark-preparation metrics**. They are not claims about independently collected evidence.

## Reproduce locally

From a repository checkout with development dependencies:

```bash
python scripts/run_declaration_completeness_benchmark.py --check
python scripts/run_declaration_completeness_benchmark.py --verify
```

For inspectable local artifacts instead of a temporary directory:

```bash
python scripts/run_declaration_completeness_benchmark.py \
  --output-dir /tmp/trustweave-declaration-consistency
```

The command writes `declaration-consistency-summary.json` and `declaration-consistency-summary.md`. Both outputs retain raw differences, list any explicit declared reconciliations separately, and state the same non-claim boundary. They must not be uploaded, represented as reviewer results, or used to assert that TrustWeave analyzed a live application.

## Fixture provenance and integrity

`examples/evaluation-corpus/declaration-completeness/provenance.json` identifies this corpus as synthetic local data, records its maintainer/update rules, and binds the benchmark definition plus every referenced fixture to an exact-file SHA-256 digest. It is an integrity record for checked-in bytes; it does **not** authenticate an external export or create independent evaluation evidence.

Verify the record before relying on a fixture update:

```bash
python scripts/verify_declaration_completeness_provenance.py
```

When a fixture changes, update the expected benchmark result, rationale, non-claim, focused regression coverage, and reviewed digest record together. Raw framework-only and manifest-only labels must remain visible; a declared mapping is still not verified semantic equivalence.

## How this can support future evaluation

A future, separately authorized study could provide participants with a fixed, sanitized task in which framework metadata and a manifest agree, disagree, or include an explicit declared mapping. Before any collection, maintainers must predefine the task pack, success criteria, setup-time recording, reviewer independence checks, privacy treatment, comparator, and result ledger. Any independent result must follow the [evaluation charter](EVALUATION_CHARTER.md), [reviewer protocol](REVIEWER_PROTOCOL.md), and [status ledger](STATUS.md).

Until then, this benchmark is **planned evidence only**. It improves reproducibility of a bounded declaration-consistency demonstration but does not advance the project’s independent-review, pilot, comparative-benchmark, adoption, archive, or external-method-review statuses.
