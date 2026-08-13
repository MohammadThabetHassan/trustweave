# Local Reviewer Workflow

This workflow turns an already-provided MCP `tools/list` snapshot into explicit review evidence. It is intentionally a **human-completed local workflow**: TrustWeave supplies deterministic inventory and draft artifacts, but never infers authority or fills trust-sensitive fields automatically.

```bash
# 1. Normalize supplied metadata only.
trustweave mcp-import --tool-list examples/mcp-tools/support-tools-list.json --output-dir artifacts/inventory

# 2. Produce an intentionally invalid draft with reviewer-required fields.
trustweave mcp-scaffold \
  --inventory artifacts/inventory/mcp-tool-inventory.json \
  --output-dir artifacts/scaffold

# 3. Reviewer resolves action classes, capabilities, sources, flows, and policy in local files.
#    The resolved files must validate as a normal TrustWeave manifest and policy.
trustweave scan --manifest reviewed.manifest.json --policy reviewed.policy.json --output-dir artifacts/review
trustweave policy-check --policy reviewed.policy.json --output-dir artifacts/policy --exit-on-review
trustweave attest --source-revision local-review --output-dir artifacts/review
trustweave verify --attestation artifacts/review/attestation.json
```

| Artifact | Reviewer responsibility | TrustWeave boundary |
|---|---|---|
| MCP inventory | Compare local metadata with the intended integration and identify changes. | Does not contact or authenticate to an MCP server. |
| Manifest scaffold | Resolve every `REVIEW_REQUIRED` action class and add sources, capabilities, and flows. | Does not create a valid manifest or select a policy decision. |
| Resolved manifest and policy | Review explicitly declared scope, source trust, action classes, paths, approval controls, and denials. | Does not execute the described agent or tool. |
| Bundle, policy review, and attestation | Inspect deterministic local evidence and retain it with the review record. | Does not sign, publish, or establish runtime enforcement. |

A completed local review is evidence about the versioned declarations supplied to TrustWeave. It is not proof that a remote MCP server, framework runtime, or deployed agent behaves identically.
