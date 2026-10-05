# Protocol: Rego equivalence under every Constraint the library ships

This protocol was written before the study it describes decided any module under a new setting,
and `scripts/rego_shipped_constraints_study.py` refuses to run unless this file hashes to the
value fixed in the script. Like the paper's other protocols, it is a hash the authors recorded in
the same working session, not an externally timestamped registration.

## Why

The exact study (`docs/EXACT_ADEQUACY_PROTOCOL_REGO.md`, `docs/rego-exact-adequacy-v1.json`)
decides equivalence under the parameter settings each module's suite tests. 43 of its 54
equivalent mutants are in modules that read parameters, so they are equivalent relative to those
settings, and the paper reports the exact score as a range: 89.5% if every one is equivalent,
76.7% if every one could be separated by a setting no test uses. This study decides them again
under every Constraint the library itself ships for the template.

## Scope

Equivalence under every shipped Constraint, not under every parameter value. A template is a
family of policies, one per instantiation, and a parameter left free turns a pattern such as an
exempt-image prefix into a relation between two values supplied with the request, which is
outside the fragment the paper decides. The shipped Constraints are the instantiations the
library's authors publish.

## Population

The 14 modules the exact study measured, read from the Gatekeeper library at the commit it
records (`e034212e94e666ab3ba69108d96222bffc8ef671`). `src/general/httpsonly/src.rego` is again
the development module and stays out of the headline. It has no new shipped setting, so the
new-setting path is exercised by a unit test on a synthetic template instead.

## Settings

A module's settings are:

- **the tested settings:** the parameter values its suite's inputs carry, derived exactly as the
  exact study derives them;
- **the shipped settings:** the `spec.parameters` of every
  `library/<group>/<name>/samples/*/constraint.yaml` for the module `src/<group>/<name>/src.rego`.
  A Constraint with no `parameters` is evaluated with the `parameters` key absent, as the library's
  own suites model a Constraint without parameters. It is not also evaluated with an empty object.

A shipped setting is new when its canonical JSON is not among the tested settings'. At the corpus
commit, the shipped Constraints are as follows. The script recomputes them and refuses to run if
they differ.

| Module | Constraint | Parameters | New |
|---|---|---|---|
| `general/automount-serviceaccount-token` | `automount-serviceaccount-token` | `absent` | no |
| `general/block-loadbalancer-services` | `block-load-balancer` | `absent` | no |
| `general/block-nodeport-services` | `block-node-port` | `absent` | no |
| `general/block-wildcard-ingress` | `block-wildcard-ingress` | `absent` | no |
| `general/disallowanonymous` | `no-anonymous-bindings` | `{"allowedRoles": ["cluster-role-1"]}` | yes |
| `general/disallowanonymous` | `no-authenticated` | `{"disallowAuthenticated": true}` | yes |
| `general/disallowinteractive` | `no-interactive-containers` | `absent` | no |
| `general/httpsonly` | `ingress-https-only` | `absent` | no |
| `general/httpsonly` | `ingress-https-only-tls-optional` | `{"tlsOptional": true}` | no |
| `general/imagedigests` | `container-image-must-have-digest` | `absent` | no |
| `pod-security-policy/allow-privilege-escalation` | `psp-allow-privilege-escalation-container` | `{"exemptImages": ["safeimages.com/*"]}` | yes |
| `pod-security-policy/host-namespaces` | `psp-host-namespace` | `absent` | no |
| `pod-security-policy/host-process` | `psp-host-process` | `absent` | no |
| `pod-security-policy/privileged-containers` | `psp-privileged-container` | `{"exemptImages": ["safeimages.com/*"]}` | yes |
| `pod-security-policy/proc-mount` | `psp-proc-mount` | `{"exemptImages": ["safeimages.com/*"], "procMount": "Default"}` | yes |
| `pod-security-policy/read-only-root-filesystem` | `full_wildcard` | `{"exemptImages": ["*"]}` | yes |
| `pod-security-policy/read-only-root-filesystem` | `psp-readonlyrootfilesystem` | `{"exemptImages": ["specialprogram"]}` | yes |
| `pod-security-policy/read-only-root-filesystem` | `wildcard-prefix` | `{"exemptImages": ["safe-images.com/*"]}` | yes |

Five of the 13 headline modules gain a new setting, and they hold 26 of the 43 parameter-relative
equivalents. The other 17 are in modules whose only shipped Constraint has no parameters, a
setting their suites already test; under every shipped Constraint they are decided by the tested
settings alone.

## Procedure

For every setting, tested or new, the exact study's procedure, unchanged:

- build the witness space from the module and every mutant that compiles, under that setting;
- take the engine's decision on every cell for the module and for every live mutant;
- a mutant is separated under the setting when some cell's decision differs.

The off-cell checks under a tested setting are the exact study's. Under a new setting they are:

- 200 perturbations of cells;
- every review the suite's inputs carry, paired with the new setting's parameters;
- 200 perturbations of those reviews.

A mutant that differs from the module on some check but on no cell is a missing cell. The random
draws continue the exact study's seeded generator, the new settings after the tested ones.

## The reproduction gate

On the tested settings alone, every module must reproduce its record in
`docs/rego-exact-adequacy-v1.json`:

- the mutants, kills and stillborn mutants;
- the live mutants, the equivalents, the distinguishable mutants and the kills through a decision
  change;
- the surviving mutants by index;
- the settings, and the cells per setting.

A module that does not reproduce is reported and not scored.

## Undecided

A module's equivalents are undecided under a Constraint when, under that new setting, the witness
space cannot be built (an unsupported construct, or the cell cap) or a missing cell is found. The
pooled score is then reported both ways: with them counted as separated survivors, and with the
module left out.

## Outcomes

This is a descriptive study with no hypothesis. It reports:

- per module, the equivalents under the tested settings, and those that stay equivalent under
  every shipped Constraint;
- every newly separated mutant, with the Constraint that separates it, an input on which the
  engine's decisions differ, and whether the suite kills it;
- the pooled exact score over the 13 headline modules under the tested and shipped settings
  together, beside 89.5% and 76.7%.

## Deviations

Any departure from this protocol is recorded in the artifact, with its reason.
