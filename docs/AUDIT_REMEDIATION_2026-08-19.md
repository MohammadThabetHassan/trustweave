# Audit Remediation Record — 2026-08-19

## Purpose and scope

This record maps the findings in the supplied **TrustWeave Full Repository Audit** to reproductions performed against the actual current `main` baseline before corrective implementation. It is not a security certification, release record, publication claim, or assertion about deployed systems. TrustWeave remains a deterministic local review tool for supplied declarations and local artifacts.

| Baseline field | Recorded value |
| --- | --- |
| Baseline SHA | `8c97cc0af2a7f7a60f180719d160cd0daf68763e` |
| Baseline package version | `0.2.3` |
| Baseline branch | `main` |
| Reproduction timestamp | 2026-08-19 |
| Reproduction method | Local pure-function and parser/workflow-contract harness, with generated current bundle inputs. |

## Reproduced findings

| Audit ID | Result on baseline | Reproduction summary | Corrective acceptance criterion |
| --- | --- | --- | --- |
| TW-AUDIT-001 | Reproduced | Removing one generated current finding and decrementing its matching summary count still passed `validate_bundle`. | Current validation rejects an omitted, duplicated, or substituted finding and requires exact expected finding coverage. |
| TW-AUDIT-002 | Reproduced | Replacing a generated finding with a validly shaped fabricated decision, severity, null rule identity, rationale, and adjusted summary still passed validation. | Current validation regenerates the expected semantic finding collection from the embedded manifest and policy. |
| TW-AUDIT-003 | Reproduced | An impossible earlier rule was reported as shadowing a possible later rule. | Only a possible earlier rule may shadow a later rule. |
| TW-AUDIT-004 | Reproduced | The typed policy parser accepted a duplicated `source_trust` entry while the public JSON Schema rejected the same input. | Tested parser and schema boundary corpus has identical accept/reject outcomes. |
| TW-AUDIT-005 | Reproduced | Changing only `approval_control.fail_closed` produced empty source/tool/capability/path changes and no diff signal. | A policy-only security weakening produces a normalized policy delta and review signal. |
| TW-AUDIT-006 | Reproduced | The canonical risk baseline and suppressions examples use legacy v1alpha1 schemas, and both are rejected by the current decision parser. | The documented quickstart uses current accepted examples and passes from a clean temporary workspace. |
| TW-AUDIT-007 | Reproduced | The publish workflow lacked explicit tag-ref, annotated-tag, and same-SHA release-gate controls. | Publishing fails closed unless it is bound to the exact annotated version tag, target SHA, and successful release gate. |

## Baseline evidence

The temporary reproduction harness used generated current `v1alpha2` bundles from the checked-in support-agent manifest and default policy; it did not modify repository files. Its recorded results were:

```text
TW-AUDIT-001: REPRODUCED — current validator accepted a missing declared finding
TW-AUDIT-002: REPRODUCED — current validator accepted a fabricated policy decision
TW-AUDIT-003: REPRODUCED — reachable later rule was reported shadowed by an impossible earlier rule
TW-AUDIT-004: REPRODUCED — parser accepted a duplicate collection rejected by schema validation
TW-AUDIT-005: REPRODUCED — fail_closed-only change produced empty standard delta sections and no signal
TW-AUDIT-006: REPRODUCED — both canonical legacy risk examples were rejected
TW-AUDIT-007: REPRODUCED — publication workflow lacked explicit tag/SHA/release-gate binding controls
```

Corrective commits must link each changed invariant to regression tests and must preserve the product’s intentionally non-executing and local-first boundary.

## Additional assurance corrections

| Audit ID | Baseline observation | Corrective acceptance criterion |
| --- | --- | --- |
| TW-AUDIT-008 | The product contract called a local bundle “tamper-evident” even though the integrity binding is a separate unsigned local statement. | Product wording distinguishes the deterministic bundle, unsigned exact-file statement, and external provenance requirement. |
| TW-AUDIT-009 | The prominent Docker OCI label was hard-coded to `0.2.0` while package metadata identified `0.2.3`. | CI passes the package version as a Docker build argument and asserts that the resulting OCI label matches it. |
| TW-AUDIT-010 | Verification without supplied artifact paths can establish only statement internal consistency. | Documentation makes supplied-file verification primary and states that statement-only verification does not inspect a reviewer’s current bytes. |

The corrective branch additionally contains executable regression coverage for the current risk-management quickstart, publication workflow static controls, and the repository’s existing versioned contract, golden-evidence, and deterministic snapshot guards. No release tag, publication, signing action, merge, or package-version change is authorized by this remediation record.
