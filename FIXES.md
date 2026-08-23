# Quality Hardening Fixes

Branch: `fix/quality-hardening-fingerprints-perf`
Baseline: `main` at `b11076c` (0.3.1 unreleased candidate)
Date: 2026-08-23

This document records the concrete defects found during an independent review of the
codebase and the fixes applied on this branch. All changes keep the product boundary
unchanged: local, deterministic, declarative review only.

## Correctness

### 1. Policy-review findings collapsed into one risk fingerprint (high)

**Files:** `src/trustweave/policy_review.py`

Every instance of `TW-POL-002`, `TW-POL-003`, `TW-POL-007`, `TW-POL-008`, and
`TW-POL-009` shared one fingerprint per policy because their subject defaulted to
`{"policy": name}` while the fingerprint material is `(evidence_kind, id, subject)`.
Consequences before this fix:

- Distinct shadowed/conflicting/untrusted-allow conditions collapsed into a single
  entry in risk review (one lexical message survived).
- Creating a baseline or suppression from that entry silently covered all current
  **and future** instances of the same rule type for that policy.

**Fix:** each rule-level finding now carries a rule-specific subject:

- `TW-POL-002`, `TW-POL-007`, `TW-POL-009`: `{"policy", "rule", "shadowing_rule"}`
- `TW-POL-003`, `TW-POL-008`: `{"policy", "rule"}`

Policy-level findings (`TW-POL-001`, `TW-POL-004/005/006`) intentionally remain
policy-scoped. Existing decisions created against old artifacts surface as
`orphaned_decisions` (visible by design) rather than being silently reused; the
`trustweave/fingerprint/v3` identity definition itself is unchanged.

Verified: a policy with two distinct shadowed rules now yields two findings with two
distinct fingerprints instead of one.

### 2. Cross-schema-version bundle diffs crashed risk review (high)

**File:** `src/trustweave/risk.py` (`_stable_metadata`)

The identical logical signal taken from a `bundle-diff/v1alpha2` artifact and a
`bundle-diff/v1alpha3` artifact produced the same fingerprint (v3 identity deliberately
excludes artifact schema version) but failed the stable-metadata agreement check,
raising `risk findings with one fingerprint have contradictory stable metadata`.

**Fix:** `_stable_metadata` now compares `(evidence_kind, identifier, subject)` only.
Cross-version duplicates deduplicate deterministically through the existing reviewer
selection key. Evidence kind, identifier, and subject must still agree, preserving the
collision-integrity guarantee.

## Performance

### 3. Quadratic bundle validation (medium-high)

**File:** `src/trustweave/bundles.py`

`_validate_finding` and `_validate_legacy_finding` rebuilt source/tool lookup dicts and
scanned every declared flow once per finding (up to `MAX_BUNDLE_FINDINGS = 10_000`),
and `{rule.id for rule in policy.rules}` was rebuilt per finding.

**Fix:** a precomputed `_ManifestIndex` (name-keyed source/tool declarations, trust and
action-class maps, frozensets of declared flow keys) plus a `policy_rule_ids` frozenset
are built once per bundle. Per-finding validation is now linear.

### 4. SARIF canonical fingerprints re-normalized the whole artifact per finding (medium)

**File:** `src/trustweave/sarif.py`, with a new helper in `src/trustweave/risk.py`

The exporter isolated each finding and ran full-artifact `normalize_findings` once per
finding to obtain its canonical identity.

**Fix:** added `risk.finding_fingerprint(artifact, finding)`, which derives the exact
same v3 identity using the same normalization helpers in constant time per finding. The
documented fallback contract is preserved: findings whose normalization is unavailable
still export with wording-derived fallback fingerprints.

### 5. Rule matching built discarded evidence records (medium)

**File:** `src/trustweave/policy_predicates.py`

`rule_matches` evaluated predicates by building the complete nine-entry explanation dict
(including sorted lists) from `checks_for_rule`, then kept only booleans.

**Fix:** `rule_matches` now evaluates the same predicates in the same order as boolean
checks with early exit. `checks_for_rule` remains the single source for explanations
(`explain-policy-decision`, coverage output).

## Robustness

### 6. Raw `KeyError` leaked from the public engine API (medium)

**File:** `src/trustweave/engine.py`

A hand-built `AgentManifest` whose flows reference undeclared sources/tools crashed
with `KeyError` inside `evaluate_manifest`; a hand-built `Policy` with an out-of-
vocabulary decision crashed inside `_default_severity`. Parsed documents can never hit
these paths, but both objects are constructible through the public API (`api.py`).

**Fix:** both paths raise domain `ValidationError` with precise messages.

### 7. Environment-dependent tests failed confusingly outside a dev checkout (medium)

**Files:** `tests/test_security_hardening.py`, `tests/test_ci_coordinator.py`,
`tests/test_cli_version.py`, `tests/test_foundation_hardening.py`,
`tests/test_reality_check_contracts.py`, `tests/test_release_reproducibility.py`

- Symlink-refusal tests crashed with `WinError 1314` on non-elevated Windows.
- Git-status side-effect checks and repository reality checks crashed when the tree
  was not a git checkout (archive/tarball installs).

**Fix:** these tests now `pytest.skip` with explicit reasons when symlinks cannot be
created or `.git` is absent. The repository reality-check invocation also uses
`sys.executable` instead of the POSIX-only `python3`.

## Toolchain and compatibility

### 8. Python 3.14 support surfaced (low)

**Files:** `.github/workflows/ci.yml`, `pyproject.toml`, `docs/contracts/compatibility-v1.json`

Added 3.14 to the CI compatibility matrix, package classifiers, and the machine-readable
compatibility contract (which enforces agreement with CI).

### 9. Repository hygiene

Removed stale untracked `build/lib` residue that shadowed lint/format gates locally.

## Verification

All gates re-run after the changes:

| Gate | Result |
|---|---|
| `pytest` (95% branch-coverage gate) | 845 passed, 10 skipped (graceful), 0 failed |
| Coverage | 96.88% |
| `ruff format --check .` | clean |
| `ruff check .` | clean |
| `mypy src` (strict) | clean |
| `bandit -r src/trustweave -q` | clean |
| Repository reality checks (changelog sync, assurance contracts, documentation markers, golden evidence, control traceability, schema coverage) | clean |
| End-to-end CLI smoke (`scan` → `test` → `policy-check` → `attest` → `report` → `verify`) | exit 0 |

Updated tests reflect intentional behavior changes only:

- `tests/test_policy_review.py` asserts the new rule-specific subjects.
- `tests/test_risk_management.py` asserts the three-field stable metadata tuple.
- `tests/test_sarif.py` imports `finding_fingerprint` for the direct strict-path check
  while keeping the export-level fallback contract intact.
