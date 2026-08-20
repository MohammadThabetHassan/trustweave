# Audit Remediation Record — 2026-08-19

## Purpose, boundary, and candidate identity

This record maps the supplied **TrustWeave Full Repository Audit** to reproductions on the recorded `main` baseline and to checked local corrective evidence on PR #20’s `fix/audit-assurance-hardening` branch. It is neither a security certification nor a release, publication, signing, merge, tag, or deployment record. TrustWeave remains a deterministic local review tool for supplied declarations and local artifacts.

| Evidence field | Recorded value |
| --- | --- |
| Baseline SHA | `8c97cc0af2a7f7a60f180719d160cd0daf68763e` |
| Baseline package version | `0.2.3` |
| Baseline branch | `main` |
| Remediation branch | `fix/audit-assurance-hardening` (PR #20; not merged by this record) |
| Corrective source candidate | `07475c05fd5d57288910b37f4029debb69cfbe13` (all corrective source, tests, mutation scope, and triage; this evidence-only record is committed separately) |
| Package-version boundary | `pyproject.toml` remains `0.2.3`; no tag, release, publish, signing, or artifact upload is authorized. |
| Baseline reproduction timestamp | 2026-08-19 |
| Corrective evidence timestamp | 2026-08-20 |

> **Evidence rule.** A final candidate SHA is intentionally not pre-claimed in a self-referential tracked record. The exact branch head and its check results are reported after the final commit and verification run. This avoids claiming that a command was executed on an SHA that did not yet exist.

## Baseline-to-final audit matrix

| Audit ID | Baseline result | Final result | Exact executable evidence |
| --- | --- | --- | --- |
| `TW-AUDIT-001` | Reproduced: removing a generated current finding and decrementing its summary count passed validation. | Fixed: validation regenerates and requires the complete semantic finding collection. | `tests/test_bundle_validation.py::test_validate_current_bundle_rejects_a_missing_declared_finding`; `::test_validate_current_bundle_rejects_duplicate_substitution_for_a_declared_flow` |
| `TW-AUDIT-002` | Reproduced: a validly shaped fabricated policy finding and adjusted summary passed validation. | Fixed: regenerated expected findings reject substituted decision, severity, rule identity, and rationale. | `tests/test_bundle_validation.py::test_validate_current_bundle_rejects_a_fabricated_policy_result` |
| `TW-AUDIT-003` | Reproduced: an impossible earlier rule was reported as shadowing a possible later rule. | Fixed: only a possible earlier rule may shadow a later rule. | `tests/test_models_contracts.py::test_policy_coverage_does_not_shadow_with_an_impossible_earlier_rule` |
| `TW-AUDIT-004` | Reproduced: parser and public schema disagreed on a duplicate declared collection. | Fixed: the tested boundary corpus has matching parser/schema accept-reject outcomes. | `tests/test_models_contracts.py::test_policy_parser_and_schema_reject_the_same_declared_boundary_violations` |
| `TW-AUDIT-005` | Reproduced: a `fail_closed`-only weakening produced no policy-review signal. | Fixed: policy-only weakening produces normalized delta and `TW-DIFF-004`; related categories `TW-DIFF-005` through `TW-DIFF-010` are also exact-payload regressions. | `tests/test_diff.py::test_bundle_diff_reports_policy_only_fail_closed_weakening`; `::test_policy_weakening_classifier_retains_each_category_in_a_combined_delta` |
| `TW-AUDIT-006` | Reproduced: canonical risk quickstart examples used rejected legacy decision schemas. | Fixed: the documented current examples pass from a clean workspace. | `tests/test_audit_regressions.py::test_risk_management_quickstart_accepts_current_examples_from_clean_workspace` |
| `TW-AUDIT-007` | Reproduced: publication workflow did not enforce exact tag, annotated-tag target, and release-gate/SHA flow. | Fixed: parsed YAML/job/dependency validation checks manual dispatch, annotated tag target, required local commands, and exact build/publish dependencies. | `tests/test_package_provenance_controls.py::test_package_provenance_controls_reject_semantically_weakened_job_graph`; `::test_package_provenance_controls_reject_missing_release_binding_control` |
| `TW-AUDIT-008` | Reproduced: local bundle wording overstated unsigned local integrity as tamper evidence. | Fixed: public assurance and provenance checks require explicit unsigned-statement and external-provenance limits. | `tests/test_foundation_hardening.py::test_repository_reality_check_accepts_tracked_public_contracts`; `scripts/reality_check.py` |
| `TW-AUDIT-009` | Reproduced: the prominent Docker OCI label was hard-coded to `0.2.0` while package metadata was `0.2.3`. | Fixed: CI validates the Docker build/smoke contract against package metadata. | `tests/test_integrations.py::test_quality_workflow_executes_real_container_build_and_smoke_contract` |
| `TW-AUDIT-010` | Reproduced: statement-only verification could be mistaken for verification of a reviewer’s current artifact bytes. | Fixed: supplied-file verification is explicit and reports individual file checks. | `tests/test_phase0_integrity.py::test_cli_verify_v1alpha3_accepts_supplied_evidence_files`; `::test_v1alpha3_individual_supplied_file_verification_reports_exact_success_contract` |

## Corrective hardening added to this branch

The following additional corrections address the assurance gaps independently reproduced against the PR #20 starting head. They preserve the intentionally local, non-executing boundary and do not change package version or release state.

| Area | Baseline gap | Final local evidence |
| --- | --- | --- |
| No-approval bundle path | A current generated bundle rendered an absent approval control as `null`, while the strict policy parser expected omission. | `tests/test_bundle_validation.py::test_current_bundle_without_approval_control_round_trips_and_self_diffs`, `::test_current_bundle_rejects_malformed_non_null_approval_control`, and `::test_cli_scan_and_self_diff_accept_policy_without_approval_control` |
| Weakening coverage | Approval removal/binding loss, unexercised rule weakening, required-control removal, and taxonomy change were not all reviewer-visible. | Exact `TW-DIFF-004`–`TW-DIFF-010` payload regressions in `tests/test_diff.py`, including the combined-category and neutral-delta classifier tests. |
| v1alpha3 policy-delta schema | The policy `before`/`after` payload was unconstrained. | `tests/test_generated_schema_conformance.py::test_real_generated_v1alpha3_policy_delta_conforms_to_its_schema`, `::test_v1alpha3_policy_delta_schema_rejects_invalid_default_decision_changes`, `::test_v1alpha3_policy_delta_schema_rejects_oversized_approval_bindings_and_text`, and `::test_v1alpha3_policy_delta_schema_rejects_malformed_rule_payload`. |
| Release-control claim | Documentation called the subset workflow a “complete” release-quality gate and the verifier used raw markers only. | Parsed workflow graph checks in `scripts/verify_package_provenance_controls.py`; regressions in `tests/test_package_provenance_controls.py`; documentation lists only the enforced commands. |
| Mutation assurance | The critical bundle parser and diff classifier were outside the configured mutation scope. | Dedicated `bundle_policy.py` and `policy_weakening.py` are in `pyproject.toml` scope. Final clean campaign: **6,444 killed / 6,566 generated / 122 survived = 98.14%**, with zero untriaged and zero `needs_regression`; exact diffs and proofs are in `docs/mutation-survivor-triage-v1.json`. |
| Version boundary | Compatibility metadata implied published `0.2.3` wrote v1alpha3. | `docs/contracts/compatibility-v1.json` distinguishes published `0.2.3` v1alpha2 from unreleased v1alpha3 and records `0.3.0` as the minimum authorized release version; `tests/test_assurance_contracts.py::test_assurance_contract_rejects_published_v1alpha3_boundary_drift` enforces it. |
| Documentation consistency | Maintained descriptions mentioned only the first two policy weakening signals. | `CHANGELOG.md`, `docs/ARCHITECTURE.md`, `docs/SCHEMA_AND_COMPATIBILITY.md`, and generated `docs/site/RULE_CATALOG.md` enumerate `TW-DIFF-004` through `TW-DIFF-010`. |

## Final local evidence executed

The bounded remediation verifier was executed successfully after the corrective implementation. It verifies root/packaged v1alpha3 schema byte parity, semantic publication-control verification, compatibility-boundary verification, and the cited regression files.

```text
python scripts/verify_audit_remediation.py
218 passed
Audit remediation verification passed: bounded semantic, schema, and regression evidence is green.
```

The final clean configured mutation campaign also completed locally with `mutmut 3.7.0` on Linux with fork support:

```text
6,566 generated; 6,444 killed; 122 survived; 0 without a selected test;
0 timed out; 0 suspicious; 98.14% killed.
```

The final full local quality gate is run after the final evidence commit. Hosted checks remain a separate observation and must be reported only for the exact pushed branch head.

## Re-run commands

Use the bounded verifier for the audit matrix, then the full local gate for release-independent quality evidence.

```bash
python scripts/verify_audit_remediation.py
ruff format --check . && ruff check . && mypy src && bandit -r src/trustweave -q && pytest && python scripts/reality_check.py && mkdocs build --strict && rm -rf dist build && python -m build && twine check dist/* && pip-audit -r requirements.txt
```

No release tag, publication, signing action, merge, or package-version change is authorized by this remediation record.
