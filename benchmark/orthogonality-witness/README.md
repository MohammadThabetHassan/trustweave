# Orthogonality witness

Structural coverage and decision-class coverage measure different things. This is the
experiment that establishes it, in real Rego, using OPA's own `--coverage`.

## The claim under test

If a suite reaching 100% structural coverage always pinned every decision the policy can
return, decision-class coverage would be implied by structural coverage and would not be
worth defining. It is not implied.

## The construction

`policy.rego` returns `deny` and `require_approval` from written rules, and `allow` only
from `default decision`. Two suites differ in exactly one assertion:

| File | The fourth test asserts |
|---|---|
| `suite_blind_test.rego` | `decision != "deny"` — executes the default line without pinning it |
| `suite_pinning_test.rego` | `decision == "allow"` — pins it |

`policy_mutant.rego` is `policy.rego` with the default changed to `require_approval`.

## Result

```
suite                                  coverage   on policy.rego   on policy_mutant.rego
suite_blind_test.rego                  100%       4/4 PASS         4/4 PASS   <- blind
suite_pinning_test.rego                100%       4/4 PASS         3/4 FAIL   <- catches
```

Both suites hold structural coverage constant at 100% with the same number of cases
against the same policy. Only the pinning suite detects the change.

Coverage records that a line executed. It does not record that the suite constrained what
that line returns. A decision reachable only through `default` is the case where the two
come apart most sharply, and the default is where fail-open lives.

## Reproduce

```bash
opa test policy.rego suite_blind_test.rego --coverage    # 100%, 4/4
opa test policy_mutant.rego suite_blind_test.rego        # 4/4 — mutation invisible
opa test policy_mutant.rego suite_pinning_test.rego      # 3/4 — mutation caught
```
