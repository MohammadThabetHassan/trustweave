# What published policy suites actually pin

`benchmark/orthogonality-witness` shows a policy suite that reaches 100% structural
coverage and still cannot detect its policy's default changing. That is a constructed
example. This study asks whether the same gap appears in policy suites people actually
publish and rely on.

## Method

`scripts/rego_suite_coverage.py` reads each `*_test.rego` through `opa parse --format json`
and records, for every `test_*` rule, which decisions the body constrains. It works on the
AST rather than the source text so it sees what OPA sees.

Suites express a decision in one of three forms, and the adapter reports which:

| Domain | Shape | Meaning |
|---|---|---|
| `labelled` | `decision == "allow"` | compares against a decision string |
| `boolean` | `is_exempt(input)` | asserts a helper rule holds, or does not |
| `violation_set` | `results := violation with input as x` then `results[r]` or `count(results) == 0` | admission policies: a non-empty violation set is a denial |

The third form needs the binding tracked. The assertion names a local variable, and only
the earlier assignment says which rule that variable holds the output of. Reading
`results[r]` without resolving `results` back to `violation` names no subject at all, which
is why an earlier version of this adapter measured 19% of the corpus and drew a confident
conclusion from it that fuller extraction later reversed.

Comparisons that do not settle the question are refused rather than guessed. `count(r) != 2`
is a real assertion, but it says nothing about whether the policy denied.

## Corpus

Four public Rego repositories, pinned in `docs/rego-suite-coverage-v1.json`:
`open-policy-agent/gatekeeper-library`, `open-policy-agent/library`,
`instrumenta/policies`, `redhat-cop/rego-policies`. 53 test files.

## Extraction

51 of 53 files (96%). The adapter reports this figure first and refuses to print a summary
below 80%, because the measured files are whichever ones it understands, which is not a
sample of anything. The two it does not read are named in the artifact:

- `open-policy-agent_library/kubernetes/lib/sar_test.rego` — every test is commented out;
  there is nothing to extract.
- `instrumenta_policies/kubernetes/security_test.rego` — asserts through a two-level helper
  (`no_violations` calls `empty`, which counts). Resolving that needs interprocedural
  analysis within the package; guessing would report a permit as a denial.

## Result

**50 of 51 suites (98%) exercise both outcomes.** For the binary permit/deny domain these
policies inhabit, published suites are not decision-blind. The straightforward version of
the hypothesis — that real suites routinely test only one side — does not hold here, and
the honest reading is that practitioners writing admission policies do test both directions.

This sharpens rather than weakens the claim behind decision-class coverage. A Gatekeeper
constraint decides over two cells. Two cells are cheap to cover and, empirically, covered.
Decision-class coverage on such a policy reduces to a check that is almost always already
satisfied, so it is not worth running. The measure earns its keep only as the decision
domain grows: TrustWeave's policy decides over trust level × action class, and the number
of cells a suite must witness grows with the product, not the line count. That is the
regime the orthogonality witness demonstrates and the regime this corpus does not contain.

## The exception

`gatekeeper-library/src/general/verifydeprecatedapi/src_test.rego` has two tests. Both
assert `count(results) == 0` — including `test_hpa_with_deprecated_api`, whose name says it
should produce a violation. Nothing in that suite fails if the constraint stops firing
entirely, which is the fail-open direction for admission control.

One instance in 51 is an existence proof, not a prevalence claim. It is reported here
because it is the failure mode the measure is designed to catch, found in the official
library, by running the measure.

## Reproducing

```bash
python scripts/rego_suite_coverage.py <corpus-dir> --json out.json
```

Requires `opa` on PATH. The corpus is Rego v0; OPA 1.x parses v1 by default, so the adapter
retries with `--v0-compatible` rather than dropping the file. Extraction logic is unit
tested against transcribed AST fixtures in `tests/test_rego_suite_coverage.py`, so it runs
in CI without the binary.
