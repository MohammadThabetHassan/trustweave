# TrustWeave CLI Reference

## Global contract

```text
trustweave [-h] {scan,test,attest,report,verify,diff,policy-check,trace-review} ...
```

All commands operate on local files. They do not execute an agent, tool configuration, model, MCP server, subprocess declared by an input, network request, credential lookup, or external business action. JSON inputs are supported by default; safe YAML loading requires the optional `PyYAML` package.

| Exit code | Meaning |
|---:|---|
| `0` | The command completed and no explicit review gate requested failure. |
| `1` | A deterministic regression failed, an attestation did not verify, or `trace-review --exit-on-review` found at least one review finding. |
| `2` | A supplied local document failed TrustWeave validation. |

## `scan`

```bash
trustweave scan --manifest PATH --policy PATH [--output-dir DIR]
```

`scan` validates the agent manifest and policy, evaluates every declared source-to-tool flow using the first matching deterministic policy rule, and writes an Agent Security Bundle.

| Input | Required | Description |
|---|---:|---|
| `--manifest` | Yes | Agent manifest in JSON or safe YAML. |
| `--policy` | Yes | Deterministic policy in JSON or safe YAML. |
| `--output-dir` | No | Artifact directory; defaults to `artifacts`. |

| Output file | Content |
|---|---|
| `agent-security-bundle.json` | Validated manifest, normalized policy, flow-level decisions, summary, and explicit limits. |

A bundle reflects **declared architecture**. It does not discover or execute an undeclared runtime path.

## `test`

```bash
trustweave test --policy PATH --scenarios PATH [--output-dir DIR]
```

`test` runs versioned synthetic scenarios over abstract source-trust and action-class labels. Scenarios are data, not instructions. The command returns `1` when an expected deterministic decision does not match.

| Input | Required | Description |
|---|---:|---|
| `--policy` | Yes | Deterministic policy in JSON or safe YAML. |
| `--scenarios` | Yes | Synthetic scenario pack in JSON or safe YAML. |
| `--output-dir` | No | Artifact directory; defaults to `artifacts`. |

| Output file | Content |
|---|---|
| `security-test-results.json` | Per-scenario expectation, observed decision, matching rule, and pass/fail summary. |

## `attest`

```bash
trustweave attest [--source-revision TEXT] [--output-dir DIR]
```

`attest` reads the bundle and synthetic test results from the selected output directory, computes local SHA-256 relationships, and writes a local hash-linked evidence statement.

| Input | Required | Description |
|---|---:|---|
| `--source-revision` | No | Revision label recorded in the statement; defaults to `GITHUB_SHA` or `local-uncommitted`. |
| `--output-dir` | No | Directory containing bundle and test results; defaults to `artifacts`. |

| Output file | Content |
|---|---|
| `attestation.json` | Hashes of local artifacts, canonical-document digests, source revision, integrity chain, and limits. |

The statement is internally verifiable but is **not signed** and is not a DSSE, SLSA, Sigstore, or transparency-log claim.

## `report`

```bash
trustweave report [--output-dir DIR]
```

`report` renders the bundle, test results, and local attestation already present in the selected output directory into a reviewer-oriented Markdown report.

| Output file | Content |
|---|---|
| `report.md` | Declared paths, decision summary, synthetic test summary, evidence chain identifier, and limits. |

## `verify`

```bash
trustweave verify --attestation PATH
```

`verify` checks the internal hash relationships recorded in a local attestation. It returns `0` for a consistent statement and `1` for a mismatch.

A successful result says only that the statement is internally consistent with its recorded local digests. It does not authenticate the author or prove that a trace, deployment, or external artifact is trustworthy.

## `policy-check`

```bash
trustweave policy-check --policy PATH [--output-dir DIR] [--exit-on-review]
```

`policy-check` statically reviews the ordered deterministic policy. It identifies a rule that an earlier rule shadows, an `allow` default decision, an untrusted-input rule that allows sensitive or external actions, and weak declaration of the approval boundary for sensitive/external paths that use `require_approval`.

When a policy declares a high-impact approval path, its optional `approval_control` object can record a mechanism label, `binds_to` fields, and `fail_closed`. The review requires bindings for `actor`, `tool`, `target`, `parameters`, `issued_at`, and `expires_at`. It emits `TW-POL-004` when no control is declared, `TW-POL-005` for missing required bindings, and `TW-POL-006` when the declared control is fail-open. These are documentation and review signals; they do not prove that a mechanism exists or was enforced.

| Input | Required | Description |
|---|---:|---|
| `--policy` | Yes | Deterministic policy in JSON or safe YAML. |
| `--output-dir` | No | Artifact directory; defaults to `artifacts`. |
| `--exit-on-review` | No | Returns `1` when one or more review findings are generated; useful for explicit CI gates. |

| Output file | Content |
|---|---|
| `policy-review.json` | Structured findings, approval-control summary, deterministic counts, and limits. |
| `policy-review.md` | Human-readable review with a declared approval-boundary table. |

A clear policy review is not approval to deploy. A finding is a human-review obligation, not an automatic block.

## `diff`

```bash
trustweave diff --base PATH --head PATH [--output-dir DIR]
```

`diff` compares two generated Agent Security Bundles. It records added, removed, and changed sources and tools; exact capability additions/removals for existing tools; declared path additions and removals; matching-rule or decision changes; and review signals for new/changed sensitive or external tools.

When an existing `sensitive` or `external` tool gains one or more declared capabilities, `diff` emits `TW-DIFF-003`. The signal requests a least-privilege and policy-coverage review; it does not prove that the capability is enabled or executable at runtime.

| Input | Required | Description |
|---|---:|---|
| `--base` | Yes | Earlier Agent Security Bundle JSON. |
| `--head` | Yes | Candidate Agent Security Bundle JSON. |
| `--output-dir` | No | Artifact directory; defaults to `artifacts`. |

| Output file | Content |
|---|---|
| `bundle-diff.json` | Structured source, tool, capability, path, decision, signal, summary, and limit inventory. |
| `bundle-diff.md` | Human-readable candidate-change report with a capability-addition/removal table. |

## `trace-review`

```bash
trustweave trace-review \
  --manifest PATH \
  --policy PATH \
  --trace PATH \
  [--output-dir DIR] \
  [--exit-on-review]
```

`trace-review` reads a local pre-recorded structured trace and compares its tool-call metadata with the manifest’s declared sources, tools, and flows. For a declared call, it applies the existing deterministic policy. It reports undeclared sources, undeclared tools, undeclared flows, observed calls that policy denies, and observed calls that require approval.

| Input | Required | Description |
|---|---:|---|
| `--manifest` | Yes | Agent manifest in JSON or safe YAML. |
| `--policy` | Yes | Deterministic policy in JSON or safe YAML. |
| `--trace` | Yes | Local trace JSON using `trustweave.dev/trace/v1alpha1`. |
| `--output-dir` | No | Artifact directory; defaults to `artifacts`. |
| `--exit-on-review` | No | Returns `1` when one or more review findings are generated; useful for explicit CI gates. |

| Output file | Content |
|---|---|
| `trace-review.json` | Summary, minimized observations, structured findings, and limits. |
| `trace-review.md` | Review-oriented Markdown that omits message contents and tool arguments. |

The detailed input and privacy contract is in [Trace Review](TRACE_REVIEW.md).

## Validation behavior

TrustWeave is intentionally strict. It rejects an unsupported schema version, missing required list, blank identifier, duplicate named declaration, unsupported trust label/action class/decision, unknown manifest reference, conflicting trace tool names, or malformed local object. Correct the input rather than bypassing validation.

## CI patterns

Use a clear trace as an ordinary CI evidence step:

```bash
trustweave trace-review \
  --manifest examples/support-agent.manifest.json \
  --policy policies/default-policy.json \
  --trace examples/traces/clear-support-trace.json \
  --output-dir artifacts/trace-clear \
  --exit-on-review
```

Use a review-required reference only to verify the gate itself. Because it intentionally returns status `1`, invert that assertion in a test script or unit test rather than treating it as a passing production policy gate.


## `mcp-profile-check`

```bash
trustweave mcp-profile-check \
  --manifest PATH \
  --profile PATH \
  [--output-dir DIR] \
  [--exit-on-review]
```

`mcp-profile-check` validates a user-supplied local MCP metadata profile and compares its declared server-tool mappings with the Agent Security Manifest. It checks the declared HTTP resource identifier for unsafe credential/query/fragment components, makes the authorization expectation visible, verifies that mapped manifest tools exist, and compares action classes.

| Input | Required | Description |
|---|---:|---|
| `--manifest` | Yes | Agent manifest in JSON or safe YAML. |
| `--profile` | Yes | Local MCP metadata profile in JSON or safe YAML. |
| `--output-dir` | No | Artifact directory; defaults to `artifacts`. |
| `--exit-on-review` | No | Returns `1` when the profile produces one or more review findings. |

| Output file | Content |
|---|---|
| `mcp-profile-review.json` | Validated metadata summary, minimized tool mappings, review findings, and explicit limits. |
| `mcp-profile-review.md` | Human-readable profile-to-manifest mapping report. |

The command never connects to an MCP endpoint or stdio transport. It does not perform server discovery, OAuth, dynamic registration, token exchange, token audience validation, capability discovery, or tool execution. See [MCP Metadata Profile Review](MCP_PROFILE.md) for the full contract.
