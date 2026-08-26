# Independent Reviewer Quickstart

## Purpose and boundary

This quickstart lets a reviewer reproduce TrustWeave’s **synthetic evaluation corpus** from a local checkout and inspect the resulting local evidence. It is designed for a technical review of reproducibility and artifact clarity. It is not a live-agent test, penetration test, security benchmark, user study, or deployment-approval procedure.

> Run only the checked-in synthetic corpus. Do not supply credentials, production manifests, customer data, proprietary traces, message content, tool arguments, live endpoint details, exploit payloads, or any material you are not authorized to disclose.

## What you need

| Requirement | Why it is needed | What it does not authorize |
|---|---|---|
| A local clone of the repository | The corpus reads checked-in synthetic fixtures and policies. | Connecting to a remote agent, MCP server, tool, or target. |
| Python 3.11 or later | TrustWeave’s documented local runtime requirement. | Installing or executing an agent framework. |
| Development dependencies | The repository’s test and documentation commands use them. | Sending telemetry, downloading corpus inputs, or submitting feedback. |
| A disposable local output directory | Lets you inspect generated artifacts without altering checked-in evidence. | Treating the output as an independent or production result. |

## Reproduce the corpus

Create a clean local environment in a checkout you control, then install the development dependencies:

```bash
git clone https://github.com/MohammadThabetHassan/trustweave.git
cd trustweave
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

First validate the checked-in corpus contract without executing any case. This checks the schema, stable corpus identity, ordered case IDs, local path boundaries, assertion shapes, and safety constraints:

```bash
python scripts/run_evaluation_corpus.py --check
```

Then execute the synthetic corpus into a new local directory. The command invokes only TrustWeave’s established local CLI against the checked-in synthetic inputs:

```bash
rm -rf /tmp/trustweave-review
python scripts/run_evaluation_corpus.py --verify --output-dir /tmp/trustweave-review
```

A successful run reports `12/12 cases passed` and exits with status `0`. A mismatch between a documented expectation and an observed local artifact exits with status `1`. An invalid corpus contract or unsafe path exits with status `2`.

## Reproduce declaration-consistency fixtures

The declaration-consistency benchmark is a separate, synthetic local fixture suite. It compares exact tool labels in supplied OpenAI Agents-style, LangGraph-style, and CrewAI-style descriptors with a supplied manifest. It neither imports a framework nor authenticates, executes, or proves the completeness of any descriptor.

First validate its checked-in contract and the exact-file provenance record, then run the fixture suite into a separate disposable directory:

```bash
python scripts/run_declaration_completeness_benchmark.py --check
python scripts/verify_declaration_completeness_provenance.py
rm -rf /tmp/trustweave-declaration-consistency-review
python scripts/run_declaration_completeness_benchmark.py \
  --verify \
  --output-dir /tmp/trustweave-declaration-consistency-review
```

A successful run reports `14/14 cases passed`. Inspect `declaration-consistency-summary.json` and `declaration-consistency-summary.md` to confirm that raw framework-only and manifest-only labels remain visible and that any declared reconciliation is reported separately. The fixture provenance record binds the checked-in synthetic bytes only; it is not an authenticity record for a real framework export or independent evaluation evidence.

## Inspect what was produced

| Local artifact | Reviewer question | Safe interpretation |
|---|---|---|
| `evaluation-corpus-summary.json` | Did every supplied synthetic case match its expected exit state and artifact assertions? | It records deterministic results for this exact local run. |
| `evaluation-corpus-summary.md` | What case categories and non-claims apply to each result? | It is a readable index of supplied-case limits, not a security verdict. |
| `/tmp/trustweave-review/TW-EVAL-*/` | Did the expected local review artifact exist for an individual case? | It shows how TrustWeave handled that one synthetic input. |
| `examples/evaluation-corpus/corpus.json` | What did the run intentionally test? | It is the complete checked-in specification for the corpus version. |
| `docs/evaluation/STATUS.md` | Which evidence is prepared versus genuinely collected? | It prevents a synthetic run from being described as independent validation. |

For a compact inspection, run:

```bash
cat /tmp/trustweave-review/evaluation-corpus-summary.md
```

Review-required cases are expected controls when their documented exit state, output artifact, and declared signals match. They are not failed runs merely because they contain findings. Conversely, a fully passing corpus is not evidence that any deployed agent is secure.

## Record a reproducible observation

Use the following local note format if you want to preserve a reproduction record. Do not include personal, proprietary, or production information.

```text
TrustWeave repository commit:
TrustWeave package version:
Python version and platform:
Corpus schema/version:
Exact command:
Observed exit code:
SHA-256 of evaluation-corpus-summary.json:
Safe observation:
Relevant case ID(s):
```

The identity and version fields can be collected locally with:

```bash
git rev-parse HEAD
python -c "import trustweave; print(trustweave.__version__)"
python --version
sha256sum /tmp/trustweave-review/evaluation-corpus-summary.json
```

## Report a safe issue or provide study feedback

A reproducible setup, corpus, or documentation observation may be submitted through the repository’s evaluation-feedback issue form. The report must use only safe synthetic details and must not be described as a study response, adoption evidence, or security result. Follow the [Community Feedback Policy](../COMMUNITY_FEEDBACK.md) and [Reviewer Protocol](REVIEWER_PROTOCOL.md) for the distinction between a public issue and an owner-approved independent-review study.

If you identify a suspected vulnerability, do **not** use the public form. Follow [SECURITY.md](../../SECURITY.md) instead.

## What this review cannot establish

This procedure cannot establish source authenticity, trace completeness, authorization correctness, live MCP behavior, runtime enforcement, attack prevention, general security efficacy, product adoption, productivity, or independent-review outcomes. Any claim in those areas requires separately collected evidence under the [Evaluation Charter](EVALUATION_CHARTER.md) and a status update supported by a human-reviewed record.
