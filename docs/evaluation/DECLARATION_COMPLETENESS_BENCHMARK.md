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

## How this can support future evaluation

A future, separately authorized study could provide participants with a fixed, sanitized task in which framework metadata and a manifest agree, disagree, or include an explicit declared mapping. Before any collection, maintainers must predefine the task pack, success criteria, setup-time recording, reviewer independence checks, privacy treatment, comparator, and result ledger. Any independent result must follow the [evaluation charter](EVALUATION_CHARTER.md), [reviewer protocol](REVIEWER_PROTOCOL.md), and [status ledger](STATUS.md).

Until then, this benchmark is **planned evidence only**. It improves reproducibility of a bounded declaration-consistency demonstration but does not advance the project’s independent-review, pilot, comparative-benchmark, adoption, archive, or external-method-review statuses.
