# Control Traceability

## Purpose

This document is generated from [`docs/contracts/control-traceability-v1.json`](contracts/control-traceability-v1.json). It links each threat-model statement to a checked-in control, source/test/evidence paths, and an explicit residual limit. The validator rejects missing paths, duplicate identifiers, orphaned controls, unlinked stated threats, and unlinked out-of-scope risks.

> A control identifies reviewable declaration-layer evidence. It does not prove complete runtime security, external certification, or deployed enforcement.

## Addressed declaration-layer threats

| ID | Threat-model statement | Controls | Explicit residual limit |
| --- | --- | --- | --- |
| `TWT-DECL-001` | Untrusted content is declared as reaching an external action | `TWC-DECLARED-FLOW` | It cannot discover undeclared paths or stop a separate runtime. |
| `TWT-DECL-002` | Confidential or conditional data is declared as reaching an external action | `TWC-DECLARED-FLOW`, `TWC-APPROVAL-BOUNDARY` | It does not implement approval or verify real identity. |
| `TWT-POLICY-001` | A high-impact path requires approval but lacks a clear boundary declaration | `TWC-APPROVAL-BOUNDARY` | It cannot prove a queue, approver identity, authorization artifact, or runtime validation exists. |
| `TWT-DIFF-001` | A policy weakens or a new flow is added | `TWC-BUNDLE-DIFF` | PR diff rendering is a future integration. |
| `TWT-SCENARIO-001` | A scenario unexpectedly changes decision | `TWC-SYNTHETIC-SCENARIOS` | The scenario covers only its declared labels, not full model behavior. |
| `TWT-POLICY-002` | An ordered policy rule is unreachable or a default permits unmatched paths | `TWC-POLICY-REVIEW` | It does not establish whether the policy intent is correct or enforce a runtime decision. |
| `TWT-DIFF-002` | A candidate manifest introduces an external/sensitive tool or changes a policy decision | `TWC-BUNDLE-DIFF` | It cannot discover undeclared behavior or determine business authorization. |
| `TWT-TRACE-001` | A local trace records an undeclared source, tool, flow, denied call, or approval-required call | `TWC-TRACE-REVIEW` | It cannot establish trace authenticity, completeness, actor identity, or incident cause. |
| `TWT-TRACE-002` | Trace evidence contains sensitive message content or tool arguments | `TWC-TRACE-PRIVACY` | The trace source itself may still require separate data-governance controls. |
| `TWT-MCP-001` | MCP metadata drifts from manifest tool declarations or action classes | `TWC-MCP-PROFILE` | It cannot discover an undeclared server capability or prove runtime enforcement. |
| `TWT-SARIF-001` | Review findings need to enter a compatible static-analysis evidence workflow | `TWC-LOCAL-SARIF` | It does not upload a finding, enable code scanning, prove consumer compatibility, or create a runtime control. |
| `TWT-MCP-002` | An HTTP MCP profile omits an authorization expectation | `TWC-MCP-PROFILE` | It does not validate OAuth, token audience, consent, or a real server policy. |
| `TWT-EVIDENCE-001` | A generated evidence document is manually edited | `TWC-LOCAL-INTEGRITY` | It cannot prove the original operator or protect unsigned files from replacement. |

## Implemented controls

| ID | Control | Code, tests, and evidence | Residual limit |
| --- | --- | --- | --- |
| `TWC-DECLARED-FLOW` | Typed manifest and policy evaluation produces deterministic findings for declared source-to-tool flows. | `src/trustweave/models.py, src/trustweave/engine.py, src/trustweave/rules.py, tests/test_trustweave.py, tests/test_models_contracts.py, docs/PRODUCT_CONTRACT.md, docs/THREAT_MODEL.md, schemas/agent-manifest.schema.json` | Findings cover only supplied declarations and do not discover or stop a live path. |
| `TWC-APPROVAL-BOUNDARY` | Policy review identifies declared high-impact flows that lack a clear approval-control boundary. | `src/trustweave/policy_review.py, src/trustweave/policy_predicates.py, tests/test_policy_review.py, tests/test_policy_attributes.py, docs/site/POLICY_REVIEW.md, schemas/policy-review-v1alpha1.schema.json` | The review cannot prove a queue, approver identity, authorization artifact, or runtime enforcement. |
| `TWC-BUNDLE-DIFF` | Bundle diff renders declared source, tool, path, rule, decision, and policy-only security changes as reviewable local evidence. | `src/trustweave/diff.py, src/trustweave/commands/evidence.py, tests/test_diff.py, tests/test_bundle_validation.py, docs/REVIEWER_WORKFLOW.md, schemas/bundle-diff-v1alpha3.schema.json` | The diff cannot discover undeclared behavior or determine business authorization. |
| `TWC-SYNTHETIC-SCENARIOS` | Synthetic scenarios produce deterministic expected-decision regression evidence from declared labels. | `src/trustweave/scenarios.py, src/trustweave/commands/test.py, tests/test_scenario_schema_contract.py, tests/test_adversarial_scenarios.py, docs/SCENARIOS.md, schemas/test-results-v1alpha1.schema.json` | Scenario evidence covers only its declared labels and not full model behavior. |
| `TWC-POLICY-REVIEW` | Deterministic policy review detects shadowed rules and review-sensitive default decisions. | `src/trustweave/policy_review.py, src/trustweave/policy_predicates.py, tests/test_policy_review.py, tests/test_policy_v2.py, docs/site/POLICY_REVIEW.md, schemas/policy-review-v1alpha1.schema.json` | The review does not determine whether a declared policy intent is correct or enforce it. |
| `TWC-TRACE-REVIEW` | Offline trace review compares minimized local trace metadata with declared manifests and policy. | `src/trustweave/trace_review.py, src/trustweave/commands/evidence.py, tests/test_trace_review.py, tests/test_integrations.py, docs/TRACE_REVIEW.md, schemas/trace-review-v1alpha1.schema.json` | Trace review cannot establish trace authenticity, completeness, actor identity, or incident cause. |
| `TWC-TRACE-PRIVACY` | Trace-review reports retain only counts, declared names, action classes, decisions, and finding identifiers. | `src/trustweave/trace_review.py, src/trustweave/report.py, tests/test_trace_review.py, tests/test_generated_schema_conformance.py, docs/THREAT_MODEL.md, docs/TRACE_REVIEW.md` | The original local trace may still require separate data-governance controls. |
| `TWC-MCP-PROFILE` | MCP profile review compares saved local metadata and declared tool mappings without discovery, transport access, or token handling. | `src/trustweave/mcp_import.py, src/trustweave/mcp_profile.py, tests/test_mcp_import.py, tests/test_mcp_profile.py, docs/MCP_IMPORT.md, docs/MCP_PROFILE.md, schemas/mcp-profile-review-v1alpha1.schema.json` | The review cannot discover undeclared server capability, validate OAuth, or prove runtime enforcement. |
| `TWC-LOCAL-SARIF` | Local SARIF conversion produces deterministic portable review evidence without upload or new security conclusions. | `src/trustweave/sarif.py, src/trustweave/commands/evidence.py, tests/test_sarif.py, tests/test_sarif_schema.py, docs/CI_INTEGRATIONS.md, docs/SCHEMA_CATALOG.md` | Local SARIF does not upload a finding, enable code scanning, or create a runtime control. |
| `TWC-LOCAL-INTEGRITY` | Local attestation and verification bind canonical evidence payloads and, when supplied, exact local artifact bytes. | `src/trustweave/evidence.py, src/trustweave/commands/evidence.py, tests/test_statement.py, tests/test_contract_hardening.py, docs/REPRODUCIBILITY.md, schemas/attestation-v1alpha3.schema.json` | Unsigned local integrity evidence cannot identify the original operator or resist complete local replacement. |

## Deliberately excluded residual risks

| ID | Out-of-scope threat | Why it remains excluded |
| --- | --- | --- |
| `TWR-OUT-001` | Prompt-injection payloads in real documents or model context. | TrustWeave evaluates supplied declarations and pre-recorded metadata; it does not parse live model context or execute a model. |
| `TWR-OUT-002` | Malicious MCP servers, skills, packages, plugins, or repository content. | TrustWeave does not connect to, discover, install, import, or invoke third-party servers or extensions. |
| `TWR-OUT-003` | Credential theft, data exfiltration, endpoint compromise, persistence, or malware. | The product does not access credentials, endpoints, or live execution environments. |
| `TWR-OUT-004` | Network vulnerabilities, cloud misconfiguration, IAM errors, or authorization bypass in a live environment. | Live infrastructure assessment is deliberately outside the local declaration-review boundary. |
| `TWR-OUT-005` | Policy bypasses in an agent runtime that has not integrated a future TrustWeave enforcement adapter. | TrustWeave generates evidence for human review and does not act as an enforcement adapter. |
| `TWR-OUT-006` | Tampering by an actor that can modify all generated files and regenerate the local attestation. | Unsigned local hash relationships cannot establish an external identity or resist full local replacement. |
| `TWR-OUT-007` | Model deception, model hallucination, or agent-planning behavior. | TrustWeave does not call, inspect, or control a model or agent planner. |

## Maintenance rule

Any change to a command, schema, evidence format, review finding, threat statement, or release control must update the JSON source and this generated guide in the same review. Run `python scripts/verify_control_traceability.py --write` only after reviewing the updated source; the default command is check-only.
