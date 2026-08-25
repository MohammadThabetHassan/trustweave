# TrustWeave Offline Reviewer Packet

## Status and purpose

This packet is **prepared, not yet executed**. It supports an owner-approved independent technical review of TrustWeave’s synthetic evaluation corpus. It is a fixed offline exercise for reproducibility and evidence-clarity review; it is not a penetration test, a live-agent evaluation, a security benchmark, a user-adoption study, or a request for production material.

> Participation is optional. Do not use credentials, personal data, customer records, production manifests, proprietary source, real traces, message content, tool arguments, live endpoints, MCP servers, external targets, or exploit payloads.

## Packet identity

The owner-approved invitation must name the exact repository commit, package version, corpus version, packet version, and analysis cutoff. Build a local manifest with the packet command before sharing files so the recipient can verify the selected bytes.

```bash
python scripts/build_evaluation_artifact.py \
  --kind reviewer-packet \
  --revision "$(git rev-parse HEAD)" \
  --output-dir /tmp/trustweave-reviewer-packet
```

This command reads checked-in public files only. It creates a local manifest and deterministic ZIP for inspection; it does not upload, contact, or recruit anyone.

## Suggested time budget

The fixed exercise is designed for **45–60 minutes**. A reviewer may stop at any point, report a safe setup blocker, or withdraw before the owner-declared analysis cutoff. The owner-approved invitation must state a private contact route for withdrawal; do not use a public issue for a withdrawal request.

## Offline tasks

| Task | Reviewer action | Permitted record |
|---|---|---|
| T1 — Setup | Use the exact checkout/package identified by the invitation. Run the corpus preflight and verification commands. | Completed, partially completed, blocked, or withdrew; safe blocker only. |
| T2 — Reproducibility | Compare the local summary with the supplied synthetic case categories. | Matches, does not match, uncertain, or not completed; affected synthetic case IDs. |
| T3 — Interpretation | Read `TW-EVAL-004` (expected clear) and `TW-EVAL-005` (expected review-required). Identify the supplied evidence, review signal, and limitation. | Correct, partly correct, incorrect, uncertain, or not completed under the owner-approved scoring guide. |
| T4 — Decision support | State whether each selected synthetic artifact would prompt further human review, confirm an existing concern, or provide no decision support. | One fixed-choice response per selected case. |
| T5 — Clarity | Rate setup instructions, output clarity, and boundary clarity. | Integer 1–5 ratings and optional redacted comment. |
| T6 — Boundary confirmation | Confirm that no sensitive/live material was used. | Required yes/no response. |
| T7 — Optional declaration consistency | Run the local four-case declaration-consistency fixture suite and identify raw differences versus any separately displayed declared reconciliation. | Completed, blocked, or not attempted; synthetic case ID and fixed-choice interpretation only. This is not a request to inspect source or a live framework. |

## Commands

From the owner-identified repository checkout with development dependencies installed:

```bash
python scripts/run_evaluation_corpus.py --check
rm -rf /tmp/trustweave-review
python scripts/run_evaluation_corpus.py --verify --output-dir /tmp/trustweave-review
cat /tmp/trustweave-review/evaluation-corpus-summary.md

python scripts/run_declaration_completeness_benchmark.py --check
rm -rf /tmp/trustweave-declaration-consistency-review
python scripts/run_declaration_completeness_benchmark.py --verify \
  --output-dir /tmp/trustweave-declaration-consistency-review
cat /tmp/trustweave-declaration-consistency-review/declaration-consistency-summary.md
```

The corpus preflight validates corpus structure and local path safety without executing a case. The corpus verification invokes only TrustWeave’s established local CLI with checked-in synthetic inputs. A successful corpus run reports `12/12 cases passed`; review-required controls remain expected when their documented exit state and artifacts match. The optional declaration-consistency command reports `4/4 cases passed` for its static fixtures; it retains raw labels and shows any explicit declared reconciliation separately. Neither command imports a framework, reads application source, contacts a service, or establishes that a supplied declaration is complete.

## Feedback and data minimization

Use [Feedback Template](FEEDBACK_TEMPLATE.md) only through an owner-approved collection route. The template does not require a name, email address, employer, organization, repository, production context, or free-text explanation. Optional comments must be redacted before any disclosure.

The project may describe a completed response as independent-review evidence only when the reviewer did not author the evaluated revision, consented to the stated use, used only the allowed synthetic materials, and completed the fixed task pack. Public feedback alone is not a study response or an adoption metric.

## Interpretation limit

Passing the corpus or completing this exercise does not establish runtime enforcement, source or trace authenticity, authorization correctness, attack prevention, general security efficacy, productivity, deployment readiness, or user adoption. Consult the [Evaluation Charter](../../../docs/evaluation/EVALUATION_CHARTER.md), [Reviewer Protocol](../../../docs/evaluation/REVIEWER_PROTOCOL.md), [Data Minimization Policy](../../../docs/evaluation/DATA_MINIMIZATION_POLICY.md), [Conflicts and Limitations](../../../docs/evaluation/CONFLICTS_AND_LIMITATIONS.md), and [Status Ledger](../../../docs/evaluation/STATUS.md) before interpreting any future collected evidence.
