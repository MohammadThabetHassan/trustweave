# Safe External Reproduction Guide

## Purpose

This guide lets an external technical user reproduce TrustWeave’s checked-in synthetic evaluation evidence without supplying private, production, proprietary, personal, or live-system material. It is a reproducibility path, not a security test, penetration test, adoption study, user study, certification, or invitation to test external targets.

> TrustWeave accepts only supplied local declarations and pre-recorded local metadata. Do not point it at a live agent, MCP server, customer system, account, endpoint, repository, or target. Do not submit credentials, tokens, keys, cookies, personal data, message content, tool arguments, real traces, or exploit payloads.

## Reproduce the synthetic corpus

Use a local checkout of the owner-identified commit. Install development dependencies, then run:

```bash
python scripts/run_evaluation_corpus.py --check
rm -rf /tmp/trustweave-external-reproduction
python scripts/run_evaluation_corpus.py --verify --output-dir /tmp/trustweave-external-reproduction
cat /tmp/trustweave-external-reproduction/evaluation-corpus-summary.md
```

The check-only command validates corpus identity, ordered case IDs, local safe paths, and assertion shapes without running a case. The verification command uses the established local CLI and twelve checked-in synthetic cases. A `12/12` passing summary means only that the documented local synthetic contract matched; expected review-required controls remain expected when their declared exit state and finding category match.

## Verify the fixed reviewer packet

If an owner has identified a fixed commit and packet manifest, verify the manifest before reviewing it:

```bash
python scripts/build_evaluation_artifact.py \
  --verify-manifest /path/to/evaluation-artifact-manifest.json
```

The verifier compares approved public-safe files and their SHA-256 digests with the local checkout. It does not authenticate the source checkout, inspect a remote repository, upload a result, or establish that a source is authoritative. Use the owner-provided commit identity and repository URL for source selection.

## Provide safe feedback

Use the [evaluation-feedback issue form](https://github.com/MohammadThabetHassan/trustweave/issues/new?template=03-evaluation-feedback.yml) only for a safe, synthetic observation about corpus clarity, setup, or a named case. Include the corpus version and case identifier where applicable. A public issue is not a private research response and will not be counted as independent-review evidence by itself.

For an owner-approved independent technical review, use the fixed [offline reviewer packet](../examples/evaluation-corpus/reviewer-packet/README.md) and the private route named in the owner’s invitation. Do not post a withdrawal request, consent response, or structured reviewer template in a public issue.

## What a reproduction can and cannot support

| A completed safe reproduction can support | It cannot support |
|---|---|
| A report that the named local synthetic commands completed, blocked, or differed from documented expected categories. | A claim of runtime enforcement, source authenticity, vulnerability absence, attack prevention, general security efficacy, adoption, productivity, or statistical generalizability. |
| A bounded corpus proposal or documentation correction with synthetic rationale. | A claim that an external reviewer study is complete without the protocol’s consent, independence, fixed-packet, and analysis conditions. |
| An owner-visible public feedback record, subject to safe triage. | Permission to merge, release, publish, alter GitHub settings, contact third parties, or run a live-system assessment. |

## Related materials

Read the [Evaluation Charter](evaluation/EVALUATION_CHARTER.md), [Reviewer Protocol](evaluation/REVIEWER_PROTOCOL.md), [Data Minimization Policy](evaluation/DATA_MINIMIZATION_POLICY.md), [Community Feedback Policy](COMMUNITY_FEEDBACK.md), [Issue Triage Procedure](ISSUE_TRIAGE.md), and [Evaluation Status Ledger](evaluation/STATUS.md) before making or interpreting a public observation.
