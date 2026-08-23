# Walkthrough: your first review, command by command

This walks through the checked-in support-agent example and shows what each command actually prints, so you know what "working" looks like before you run it on your own agent. Every output below is real.

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

One file so far. The bundle records every declared flow — source × tool — with its decision. Exit code `0`.

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

Five scenarios ran: trusted→read allowed, untrusted→external denied, and so on. If someone later edits the policy in a way that breaks an intended decision, this command exits non-zero — wire it into CI and policy regressions die in review.

## 3. Attest the evidence

```shell
trustweave attest --source-revision local --output-dir artifacts
```

Output:

```text
Wrote local evidence attestation: artifacts/attestation.json
```

The attestation hash-links the artifacts produced above. It is **not** a signature — no identity is attached. Its job is letting a reviewer later confirm the files they're reading are the files this run produced.

## 4. Generate the report

```shell
trustweave report --output-dir artifacts
```

Output:

```text
Wrote Markdown report: artifacts/report.md
```

Open `artifacts/report.md`. The interesting part:

| Source | Trust | Tool | Decision | Rule |
|---|---|---|---|---|
| customer_request | trusted | search_knowledge_base | **allow** | TW-001 |
| customer_request | trusted | lookup_customer_record | **deny** | default |
| customer_record | conditional | send_mock_email | **require_approval** | TW-002 |
| knowledge_base_document | untrusted | send_mock_email | **deny** | TW-004 |

Read the `default` row carefully: nobody wrote a rule for trusted→sensitive, so it fails closed to deny. If that lookup is supposed to be allowed, the manifest author needs to add a rule — and a scenario locking it in. This is the review conversation TrustWeave exists to start.

## 5. Verify the bytes haven't changed

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

Supplying all three paths checks those exact files against the attestation. Running only `--attestation` verifies the statement's internal consistency — weaker, and the CLI reference explains when that distinction matters.

## Next steps

- Point `scan` at your own agent. If you have a LangGraph / OpenAI Agents / CrewAI setup or a saved MCP `tools/list` snapshot, see [integration routes](INTEGRATIONS.md) for import commands.
- Something failed? Check [troubleshooting](TROUBLESHOOTING.md) — exit codes are stable and each maps to a cause.
- Want to see what the decisions mean in practice? The [research-assistant demo](../../demo/research-assistant/) reviews a realistic agent end to end, including a diff that catches a weakened approval control.
