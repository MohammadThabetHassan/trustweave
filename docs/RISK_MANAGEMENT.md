# Local Risk Management

## Purpose

`trustweave risk-check` turns findings already present in supplied **local** review artifacts into a deterministic reviewer queue. It provides a narrow management layer for fixed fingerprints, severity gates, temporary baselines, and temporary suppressions. It does not detect new runtime behavior, contact a ticket system, authenticate an approver, or waive a real security obligation.

> A baseline or suppression is a time-bounded documentation decision, not a remediation, authorization, exception approval, or proof that an agent system is secure.

## Command

```bash
trustweave --generated-at 2026-08-13T00:00:00+00:00 risk-check \
  --input artifacts/policy-review.json \
  --input artifacts/review/bundle-diff.json \
  --baseline examples/risk-management/risk-baseline.example.json \
  --suppressions examples/risk-management/risk-suppressions.example.json \
  --fail-on high \
  --output artifacts/risk-review.json
```

The command accepts one or more existing local review artifacts that contain `findings`. It normalizes each finding to the following stable, reviewer-visible shape.

| Field | Meaning |
| --- | --- |
| `artifact_schema_version` | The supplied artifact contract that produced the finding. |
| `id` | The existing TrustWeave review identifier. |
| `severity` | `critical`, `high`, `medium`, `low`, or `info`. Legacy `review` findings normalize to `medium`. |
| `message` | The supplied local finding message. |
| `fingerprint` | SHA-256 over the normalized schema version, identifier, severity, and message. |
| `risk_state` | `new`, `baselined`, `suppressed`, `expired_baseline`, or `expired_suppression`. |

The command writes both `risk-review.json` and a reviewer-facing `risk-review.md` summary by default. The default `--fail-on high` exits with status `1` only for active `critical` or `high` findings. `--fail-on medium`, `low`, or `info` tightens the gate. `--fail-on none` reports the evidence without changing the exit code. A finding that is baselined or suppressed before its expiry is not active; an expired entry becomes active again deterministically.

To retain active risk evidence in a separately authorized SARIF consumer, pass the local JSON output to `trustweave sarif --risk-review artifacts/risk-review.json`. Only `new`, `expired_baseline`, and `expired_suppression` findings are exported; baselined and suppressed entries remain visible in the local risk-review report but are intentionally omitted from the active SARIF results. The canonical risk fingerprint is preserved as `trustweave/risk-v1`.

## Baseline contract

A baseline is an explicit temporary acceptance of a known local finding. It uses `trustweave.dev/risk-baseline/v1alpha1` and must record the finding fingerprint, a human-readable reason, and an ISO 8601 timestamp with a UTC offset in `expires_at`.

```json
{
  "schema_version": "trustweave.dev/risk-baseline/v1alpha1",
  "baseline": [
    {
      "fingerprint": "<64-character-sha256>",
      "reason": "A bounded, reviewer-owned acceptance while a declared control is delivered.",
      "expires_at": "2026-09-30T00:00:00+00:00"
    }
  ]
}
```

## Suppression contract

A suppression has the same required fields and uses `trustweave.dev/risk-suppressions/v1alpha1`. Use it only when a specific finding is temporarily inapplicable to the reviewed local evidence. Do not use a suppression to hide a persistent control gap; make the scope and expiry short, and replace it with a baseline only when maintainers consciously accept the remaining review obligation.

## Reviewer procedure

1. Generate the policy, diff, trace, or MCP-profile review artifacts from checked-in local inputs.
2. Run `risk-check` with a fixed `--generated-at` value in CI or a reproducible review record.
3. Treat `new` and expired states as active review work. Address the declaration or control first.
4. If a temporary exception is genuinely necessary, add the exact fingerprint with a reason and expiry in the appropriate reviewed file.
5. Keep baseline and suppression changes in a separate, reviewer-visible commit. Remove entries once the underlying finding is resolved.

This procedure preserves TrustWeave’s non-executing boundary: it evaluates only supplied artifact metadata and has no external side effects.
