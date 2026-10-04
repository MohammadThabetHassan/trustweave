# Walkthrough: your first review, command by command

This page runs the checked-in support-agent example and shows what each command prints, so you
know what a working run looks like before you use your own agent. Every output below is copied
from a real run.

## 0. Install

```shell
python -m pip install --upgrade trustweave
```

Python 3.11 or later. If your manifests are YAML rather than JSON: `pip install 'trustweave[yaml]'`.

## 1. Scan the declared boundaries

```shell
git clone https://github.com/MohammadThabetHassan/trustweave.git
cd trustweave

trustweave scan \
  --manifest examples/support-agent.manifest.json \
  --policy policies/default-policy.json \
  --output-dir artifacts
```

Output:

```text
Wrote Agent Security Bundle: artifacts/agent-security-bundle.json
```

The bundle records the decision for every declared flow, that is, every pair of source and tool.
Exit code `0`.

## 2. Test the policy against synthetic scenarios

```shell
trustweave test \
  --policy policies/default-policy.json \
  --scenarios scenarios/default-scenarios.json \
  --output-dir artifacts
```

Output:

```text
Wrote synthetic test results (passed): artifacts/security-test-results.json
```

Five scenarios ran; for example, trusted→read is allowed and untrusted→external is denied. If a
later policy edit breaks an intended decision, this command exits non-zero, so running it in CI
catches policy regressions during review.

## 3. Attest the evidence

```shell
trustweave attest --source-revision local --output-dir artifacts
```

Output:

```text
Wrote local evidence attestation: artifacts/attestation.json
```

The attestation hash-links the artifacts produced above. It is **not** a signature and carries no
identity; it lets a reviewer confirm later that the files they are reading are the files this run
produced.

## 4. Generate the report

```shell
trustweave report --output-dir artifacts
```

Output:

```text
Wrote Markdown report: artifacts/report.md
```

The core of `artifacts/report.md` is the decision table:

| Source | Trust | Tool | Decision | Rule |
|---|---|---|---|---|
| customer_request | trusted | search_knowledge_base | **allow** | TW-001 |
| customer_request | trusted | lookup_customer_record | **deny** | default |
| customer_record | conditional | send_mock_email | **require_approval** | TW-002 |
| knowledge_base_document | untrusted | send_mock_email | **deny** | TW-004 |

The `default` row deserves attention. No rule covers trusted→sensitive, so the policy fails closed
and denies it. If that lookup should be allowed, the policy needs a rule for it and a scenario that
pins the decision. Surfacing decisions like this one for review is what TrustWeave is for.

## 5. Verify that the files are unchanged

```shell
trustweave verify \
  --attestation artifacts/attestation.json \
  --bundle artifacts/agent-security-bundle.json \
  --test-results artifacts/security-test-results.json
```

Output:

```text
v1alpha3 attestation bindings are internally consistent with supplied-file verification
```

Supplying all three paths checks those exact files against the attestation. With `--attestation`
alone, `verify` checks only the statement's internal consistency, which is a weaker check; the CLI
reference explains when the difference matters.

## Next steps

- Point `scan` at your own agent. For a LangGraph, OpenAI Agents or CrewAI setup, or a saved MCP
  `tools/list` snapshot, the [integration routes](INTEGRATIONS.md) give the import commands.
- If a command fails, [troubleshooting](TROUBLESHOOTING.md) maps each stable exit code to its
  cause.
- The [research-assistant demo](https://github.com/MohammadThabetHassan/trustweave/tree/main/demo/research-assistant)
  reviews a realistic agent end to end, including a diff that catches a weakened approval control.
