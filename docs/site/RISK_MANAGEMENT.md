# Risk identity, baselines, and suppressions

`risk-check` turns canonical findings already present in supplied **local** review artifacts into a deterministic reviewer queue. It does not discover runtime behavior, contact a ticket system, authenticate an approver, or waive a security obligation.

```shell
trustweave --generated-at 2026-08-13T00:00:00+00:00 risk-check \
  --input artifacts/policy-review.json \
  --baseline risk-baseline.json \
  --suppressions risk-suppressions.json \
  --fail-on high \
  --output artifacts/risk-review.json
```

## Stable identity and state

Every supported local finding receives a `trustweave/fingerprint/v3` value. The fingerprint is a SHA-256 identity over evidence kind, review identifier, and normalized stable subject. Message wording, review severity, timestamps, artifact paths, temporary directories, and output locations do not change the fingerprint; severity remains a separate reviewer-visible property.

| State | Meaning | Active for a severity gate |
| --- | --- | --- |
| `new` | No matching live temporary record exists | Yes |
| `baselined` | A matching baseline exists before its expiry | No |
| `suppressed` | A matching suppression exists before its expiry | No |
| `expired_baseline` | A matching baseline has reached expiry | Yes |
| `expired_suppression` | A matching suppression has reached expiry | Yes |

A baseline is a temporary, reviewer-visible acceptance of a known local finding. A suppression is a temporary record that a specific finding is inapplicable to the supplied evidence. Both use an exact finding fingerprint, a non-empty reason, and an ISO 8601 expiry with a UTC offset. Neither record proves remediation, identity, authorization, or production security.

## Reviewer workflow

Generate policy, diff, trace, or MCP-profile review artifacts from checked-in local inputs. Run `risk-check` with a fixed `--generated-at` value when a reproducible review record is needed. Treat `new` and expired records as active reviewer work. Correct the declaration or control first; add a temporary baseline or suppression only when a reviewer explicitly records the reason and short-lived expiry in a visible change.

By default, `--fail-on high` exits nonzero for active critical or high findings. Tighten the gate with `medium`, `low`, or `info`, or use `none` to report without changing the exit code. `trustweave sarif --risk-review artifacts/risk-review.json` exports only active risk states; temporarily baselined and suppressed records remain visible in the local risk review but are not active SARIF results.

> A risk review organizes declared local evidence. It is not a release approval, a workflow engine, a deployment decision, or a statement about a deployed agent.
