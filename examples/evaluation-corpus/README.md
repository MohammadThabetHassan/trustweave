# TrustWeave Synthetic Evaluation Corpus

This directory contains a **local-only synthetic corpus** for checking whether TrustWeave produces the documented review categories from supplied declarations and minimized metadata. It is an evaluation foundation, not a security benchmark for live agents or infrastructure.

## Run the corpus

From a checked-out TrustWeave repository with the development dependencies installed, run:

```bash
python scripts/run_evaluation_corpus.py --verify
```

The runner creates a temporary local directory by default. To retain outputs for inspection, provide an explicit local path:

```bash
python scripts/run_evaluation_corpus.py \
  --verify \
  --output-dir /tmp/trustweave-evaluation-corpus
```

The retained directory contains one subdirectory per case plus:

- `evaluation-corpus-summary.json`, a machine-readable outcome record; and
- `evaluation-corpus-summary.md`, a human-readable table and case limits.

A successful verification prints `12/12 cases passed` and exits with status `0`. A case mismatch exits with status `1`; an invalid corpus manifest or unsafe path exits with status `2`.

## Corpus design

The `corpus.json` manifest defines twelve stable, synthetic cases. It includes schema-validation failures, clear and review-required policy cases, declared-bundle diff controls, minimized trace-review controls, and local MCP metadata-profile controls. Four cases are explicit clear/no-finding controls; review-required cases are not treated as failures when their documented exit and findings match.

| Case family | What it checks | What it does not check |
|---|---|---|
| Manifest validation | Required declared trust and data-classification fields fail closed. | Whether a supplied manifest reflects a live system. |
| Policy review | Static rule structure and declared approval-boundary review signals. | Runtime policy enforcement or deployment authorization. |
| Bundle diff | Declared capability and approval-control deltas. | Undeclared code, configuration, or deployed-system changes. |
| Trace review | Supplied minimized metadata against supplied declarations. | Trace authenticity, completeness, message content, or tool arguments. |
| MCP profile review | Supplied local profile mappings and declared action classes. | Server discovery, network reachability, OAuth, token handling, or live capabilities. |

## Safety and privacy rules

The corpus is intentionally self-contained. It uses no network client, live server, credential, model call, telemetry collector, executable tool configuration, production trace, personal data, proprietary source, or real target. The two malformed fixtures demonstrate fail-closed validation only; they do not contain adversarial payloads.

Do not add an external URL, secret, token-like URI component, live host, downloaded asset, message content, tool argument, customer record, or real agent trace to this directory. Propose a new case through the evaluation-feedback route described in [Community Feedback Policy](../../docs/COMMUNITY_FEEDBACK.md).

## Interpretation limit

> Passing this corpus demonstrates only that the current TrustWeave revision conforms to expected behavior on the supplied synthetic inputs. It does **not** demonstrate runtime enforcement, input authenticity, attack prevention, general security efficacy, user adoption, or productivity outcomes.

See the [Evaluation Charter](../../docs/evaluation/EVALUATION_CHARTER.md), [Reviewer Protocol](../../docs/evaluation/REVIEWER_PROTOCOL.md), and [Evaluation Status Ledger](../../docs/evaluation/STATUS.md) for the evidence rules governing future independent review.
