# Synthetic declaration-completeness benchmark

## Purpose

This prepared benchmark addresses one narrow evaluation question: **when supplied static framework metadata and a supplied TrustWeave manifest disagree on exact tool labels, can a reviewer reproduce that disagreement as a local review artifact?**

It is intentionally a local, deterministic fixture suite. It does not import or execute a framework, inspect application source, read an environment, load a credential, connect to a service, execute a tool, or observe a running agent. It does not prove that either declaration is complete. The benchmark is **not yet an independent evaluation result** and must not be described as a framework-security scan, runtime-completeness check, or measure of vulnerability detection.

## What it compares

Each benchmark case contains two checked-in inputs:

| Input | Meaning | Trust boundary |
| --- | --- | --- |
| Framework descriptor | An already-provided OpenAI Agents-style JSON export containing agent names and static tool labels. | It is review data; its authenticity and completeness are not established. |
| TrustWeave manifest | An explicitly supplied local manifest containing declared tool names. | It is a declaration; it is not a representation proven to match an executable agent. |

The runner normalizes the supplied descriptor with the existing `framework-import` contract and compares **exact tool-label sets** with the validated manifest tool names. It reports labels that are missing from the manifest and labels that appear only in the manifest.

> Exact label agreement is a bounded consistency signal, not proof that either input is complete, equivalent to source code, reachable at runtime, authorized, or secure.

## Synthetic cases and expected metrics

| Case | Fixture condition | Expected static result | Metric contribution |
| --- | --- | --- | --- |
| `TW-COMP-001` | The supplied descriptor and manifest list the same three tool labels. | `complete` | One exact-label agreement control. |
| `TW-COMP-002` | The supplied descriptor contains `webhook_notify`, while the supplied manifest omits it. | `mismatch`; one `missing_from_manifest` label. | One intentional disagreement control. |

The benchmark reports the following fixture-level metrics only:

| Metric | Definition | Excluded conclusion |
| --- | --- | --- |
| Exact-label agreement | Cases whose supplied tool-label sets are identical. | That an agent, framework configuration, or source tree is complete. |
| Missing-from-manifest labels | Tool labels present in supplied framework metadata but absent from the supplied manifest. | That a live capability exists, is reachable, or is unsafe. |
| Manifest-only labels | Tool names present in the supplied manifest but absent from supplied framework metadata. | That the descriptor is stale or malicious. |
| Fixture conformance | Whether observed output equals the checked-in expected output. | Detection rate, false-positive rate, or security efficacy on real agents. |

These are **benchmark-preparation metrics**. They are not user-study, adoption, performance, comparative, or external-validation metrics.

## Reproduce locally

From a repository checkout with development dependencies:

```bash
python scripts/run_declaration_completeness_benchmark.py --check
python scripts/run_declaration_completeness_benchmark.py --verify
```

For inspectable local artifacts instead of a temporary directory:

```bash
python scripts/run_declaration_completeness_benchmark.py \
  --output-dir /tmp/trustweave-declaration-completeness
```

The command writes a JSON summary and a Markdown report. Both state the same non-claim boundary. They must not be uploaded, represented as reviewer results, or used to assert that TrustWeave analyzed a live application.

## How this can support future evaluation

A future, separately authorized study could provide participants with a fixed, sanitized task in which framework metadata and a manifest intentionally agree or disagree. Before any collection, maintainers must predefine the comparator, task pack, success criteria, setup-time recording, reviewer independence checks, privacy treatment, and result ledger. Any independent result must follow the [evaluation charter](EVALUATION_CHARTER.md), [reviewer protocol](REVIEWER_PROTOCOL.md), and [status ledger](STATUS.md).

Until then, this benchmark is **planned evidence only**. It improves reproducibility of a bounded declaration-consistency demonstration but does not advance the project’s independent-review, pilot, comparative-benchmark, adoption, archive, or external-method-review statuses.
