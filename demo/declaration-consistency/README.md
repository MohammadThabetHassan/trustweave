# Declaration-consistency case demos

This directory contains a terminal-style walkthrough for every checked-in declaration-consistency fixture. Each animation opens with a readable case briefing—its scenario, review question, expected bounded result, and reason for inclusion—then advances through an actual local run of [`run-case.sh`](run-case.sh), and ends with a scope reminder. Each matching `.cast` file records that same paced walkthrough in an asciinema-compatible format.

> **Scope boundary:** These are synthetic local fixtures. They compare exact labels in supplied static descriptors and supplied TrustWeave manifests. They do not import or execute OpenAI Agents, LangGraph, or CrewAI; authenticate the inputs; inspect source; establish runtime reachability; or prove security.

## Optional developer-demo tooling boundary

The checked-in GIFs and casts are **review illustrations**, not TrustWeave runtime output, and the `demo/` directory is not imported by the `trustweave` package or installed as a TrustWeave CLI command. The Bash walkthrough and Pillow renderer are optional maintainer tools for regenerating synthetic demonstrations on a POSIX host; Windows users may inspect the checked-in GIFs, casts, fixtures, and Python benchmark without running those helper scripts.

`run-case.sh` accepts one exact checked-in `TW-COMP-NNN` identifier and creates or replaces only `demo/declaration-consistency/artifacts/<case-id>/`. It does not accept an output-path argument, read credentials, import a framework, contact a service, or operate on a deployed target. The renderer invokes that same local fixture command when an authorized maintainer deliberately regenerates illustrations.

## Asset budget

The project keeps the full visual catalog because each animation has a matching replayable cast and benchmark fixture. To keep that convenience proportionate, tests enforce an asset budget: each GIF must be at most **600 KiB**, each cast at most **12 KiB**, the complete GIF gallery at most **8 MiB**, and the checked-in font asset at most **400 KiB**. New cases must satisfy the same budget or use a deliberately reviewed alternative presentation design.

## Reproduce one case

```shell
./run-case.sh TW-COMP-011
```

The runner first validates the selected checked-in fixture, verifies the complete fixture-provenance record, evaluates exactly that case, and writes its local report to `artifacts/TW-COMP-011/`. In the GIFs, the case briefing and result screens remain visible for several seconds; command output advances in short, readable stages rather than as a rapid full transcript. The marked block between **“Captured terminal output begins”** and **“Captured terminal output ends”** is the unmodified output emitted by `run-case.sh`; the briefing, markers, pacing, and final reminder are renderer additions and are intentionally shown as such.

## Case walkthroughs

| Case | What the actual local comparison shows | GIF | Cast |
| --- | --- | --- | --- |
| `TW-COMP-001` | Exact agreement across a complete OpenAI Agents-style static tool surface. | [demo](cases/TW-COMP-001.gif) | [cast](cases/TW-COMP-001.cast) |
| `TW-COMP-002` | A framework-only static label (`webhook_notify`) requiring review. | [demo](cases/TW-COMP-002.gif) | [cast](cases/TW-COMP-002.cast) |
| `TW-COMP-003` | A manifest-only static label (`audit_log`) requiring review. | [demo](cases/TW-COMP-003.gif) | [cast](cases/TW-COMP-003.cast) |
| `TW-COMP-004` | Raw bidirectional differences plus transparent declared reconciliation. | [demo](cases/TW-COMP-004.gif) | [cast](cases/TW-COMP-004.cast) |
| `TW-COMP-005` | An empty framework inventory against a single manifest label. | [demo](cases/TW-COMP-005.gif) | [cast](cases/TW-COMP-005.cast) |
| `TW-COMP-006` | Minimal one-tool exact agreement. | [demo](cases/TW-COMP-006.gif) | [cast](cases/TW-COMP-006.cast) |
| `TW-COMP-007` | Multi-agent overlapping labels deduplicated for comparison. | [demo](cases/TW-COMP-007.gif) | [cast](cases/TW-COMP-007.cast) |
| `TW-COMP-008` | Multiple framework-only static labels left unresolved. | [demo](cases/TW-COMP-008.gif) | [cast](cases/TW-COMP-008.cast) |
| `TW-COMP-009` | Multiple manifest-only static labels left unresolved. | [demo](cases/TW-COMP-009.gif) | [cast](cases/TW-COMP-009.cast) |
| `TW-COMP-010` | Bidirectional unresolved static-label drift. | [demo](cases/TW-COMP-010.gif) | [cast](cases/TW-COMP-010.cast) |
| `TW-COMP-011` | Partial reconciliation that leaves remaining labels unresolved. | [demo](cases/TW-COMP-011.gif) | [cast](cases/TW-COMP-011.cast) |
| `TW-COMP-012` | A LangGraph-style graph-only descriptor boundary. | [demo](cases/TW-COMP-012.gif) | [cast](cases/TW-COMP-012.cast) |
| `TW-COMP-013` | Exact agreement for a CrewAI-style agent/task descriptor. | [demo](cases/TW-COMP-013.gif) | [cast](cases/TW-COMP-013.cast) |
| `TW-COMP-014` | A CrewAI-style framework-only static label. | [demo](cases/TW-COMP-014.gif) | [cast](cases/TW-COMP-014.cast) |

## Start with these four controls

The full catalog is useful for a method review, but a first-time reader can understand the bounded workflow through four representative cases.

| Start here | Why this case is representative | Result to inspect |
| --- | --- | --- |
| [`TW-COMP-002`](cases/TW-COMP-002.gif) | Shows a raw framework-only label that remains unresolved. | `webhook_notify` is listed only in supplied framework metadata. |
| [`TW-COMP-004`](cases/TW-COMP-004.gif) | Shows raw bidirectional differences plus fully declared local reconciliation. | Raw labels remain visible even when every difference is paired. |
| [`TW-COMP-011`](cases/TW-COMP-011.gif) | Shows that a partial reconciliation does not conceal remaining mismatches. | One label on each side remains unresolved. |
| [`TW-COMP-014`](cases/TW-COMP-014.gif) | Shows the same bounded comparison against a CrewAI-style descriptor. | A framework-only label remains a review signal, not a runtime claim. |

![Terminal walkthrough for TW-COMP-002](cases/TW-COMP-002.gif)

![Terminal walkthrough for TW-COMP-004](cases/TW-COMP-004.gif)

![Terminal walkthrough for TW-COMP-011](cases/TW-COMP-011.gif)

![Terminal walkthrough for TW-COMP-014](cases/TW-COMP-014.gif)

## Full catalog

The complete catalog is retained for reproducibility and method review. The four cases above are the recommended first reading path; open the disclosure below when you need to inspect every rendered walkthrough.

<details>
<summary><strong>Browse all 14 rendered case walkthroughs</strong></summary>

### `TW-COMP-001` — complete declared tool surface

![Terminal walkthrough for TW-COMP-001](cases/TW-COMP-001.gif)

### `TW-COMP-002` — framework-only static tool label

![Terminal walkthrough for TW-COMP-002](cases/TW-COMP-002.gif)

### `TW-COMP-003` — manifest-only static tool label

![Terminal walkthrough for TW-COMP-003](cases/TW-COMP-003.gif)

### `TW-COMP-004` — declared reconciliation

![Terminal walkthrough for TW-COMP-004](cases/TW-COMP-004.gif)

### `TW-COMP-005` — empty inventory boundary

![Terminal walkthrough for TW-COMP-005](cases/TW-COMP-005.gif)

### `TW-COMP-006` — single-tool agreement

![Terminal walkthrough for TW-COMP-006](cases/TW-COMP-006.gif)

### `TW-COMP-007` — multi-agent overlap

![Terminal walkthrough for TW-COMP-007](cases/TW-COMP-007.gif)

### `TW-COMP-008` — multiple framework-only labels

![Terminal walkthrough for TW-COMP-008](cases/TW-COMP-008.gif)

### `TW-COMP-009` — multiple manifest-only labels

![Terminal walkthrough for TW-COMP-009](cases/TW-COMP-009.gif)

### `TW-COMP-010` — bidirectional unresolved drift

![Terminal walkthrough for TW-COMP-010](cases/TW-COMP-010.gif)

### `TW-COMP-011` — partial reconciliation

![Terminal walkthrough for TW-COMP-011](cases/TW-COMP-011.gif)

### `TW-COMP-012` — LangGraph-style descriptor boundary

![Terminal walkthrough for TW-COMP-012](cases/TW-COMP-012.gif)

### `TW-COMP-013` — CrewAI-style agreement

![Terminal walkthrough for TW-COMP-013](cases/TW-COMP-013.gif)

### `TW-COMP-014` — CrewAI-style mismatch

![Terminal walkthrough for TW-COMP-014](cases/TW-COMP-014.gif)

</details>

## Regenerate the gallery

Install the small optional renderer extra on a POSIX developer host, then run the deterministic renderer from the repository root:

```shell
pip install -e '.[demo]'
python3 scripts/render_declaration_consistency_demos.py
```

It executes every case through `run-case.sh`, writes a matching terminal cast, proves that each marked cast section exactly matches the current runner output, and rebuilds each GIF with a case-specific briefing, paced command stages, and a final limit reminder. The renderer uses the checked-in [`DejaVu Sans Mono` font asset](assets/DejaVuSansMono.ttf) and retains its [upstream license notice](assets/DEJAVU_FONT_LICENSE.txt), so contributors do not need a host-specific font path. The generated files are review illustrations for this checked-in synthetic corpus only; they are not evidence of a live framework run.
