# Protocol: real faults in real Rego policy, exposed by the suite strategies

This protocol was written before the study it describes computed any outcome, and
`scripts/rego_real_faults_study.py` refuses to run on the population below unless this file
hashes to the value fixed in the script. Like the paper's other protocols, it is a hash the
authors recorded in the same working session, not an externally timestamped registration; the
commit that adds it precedes the commit that adds the study's results. The candidate commits
were listed and classified, from their messages and diffs, before any of them was analysed; the
classification is part of this file, so its hash fixes it.

## Why

Every payoff result in the paper scores suites against mutants the authors' own operators
produce, and a reader can fairly object that a criterion built from the same guards the
operators edit is close to built to detect them. This study scores the same strategies against
faults nobody seeded: changes that the maintainers of two policy libraries made to fix their
own policies.

## The faults

**Corpora.** The histories of the Gatekeeper library (pinned at
`e034212e94e666ab3ba69108d96222bffc8ef671`) and of Google's Config Validator policy library
(pinned at `4a2abc741583884dd38ca3b9bf2ff5a4d205a609`), the two Rego corpora of the paper whose
modules are tested with `opa test`. The Red Hat community library, the third corpus with a
history, tests its policies through conftest fixtures that the instrument does not run; its
candidates are listed below and excluded by name.

**Candidates.** A non-merge commit whose subject matches
`\b(fix|fixes|fixed|bug|incorrect|wrong|regression|false (positive|negative)|bypass|missing|handle|handles|broken)\b`
(case-insensitive) and that modifies between one and three non-test policy modules
(`src/*/*/src.rego` in Gatekeeper, `validator/*.rego` in Config Validator,
`policy/**/src.rego` in Red Hat). Each modified module is one candidate: 72 in all.

**Classification.** A candidate is a *behaviour fix* when its commit message describes
correcting what the policy decides (a bug, a wrong field, type or operator, a missing case, a
false positive or negative), and is *excluded* when the message describes messages, comments,
documentation links, formatting, style or lint, copyright, package or parameter renaming, or
test data, even when its diff also touches logic. The table at the end gives every candidate's
class; 39 are behaviour fixes, 34 of them in the two corpora studied.

**A fault.** For a behaviour fix in commit *c* to module *m*: the policy in use, *P*, is *m* at
*c*'s parent, and the fix, *F*, is *m* at *c*. Each version is evaluated with its own commit's
shared libraries (Gatekeeper's `src/rego/lib_*`, Config Validator's `lib/` and
`validator/test_utils.rego`).

**Development.** One fault per input convention was used to build the harness before this
protocol fixed the population: Gatekeeper's #2 (`4416aa12b4`, proc-mount) and Config
Validator's #34 (`0f5a5d99a7`, gke_disable_legacy_endpoints). Both are reported, flagged, and
not pooled.

## What is measured

The question is the one the paper's real-edit analysis of Cedar asks: would a suite built from
the policy in use have *exposed* the change, that is, contained an input on which *P* and *F*
decide differently? It measures exposure of the behaviour change, not whether a test's expected
output was right; a suite consistent with *P* that contains such an input fails on *F*, and one
consistent with *F* fails on *P*.

**Instantiations.** The distinct parameter values the module's suite supplies, recorded as the
exact study records them (a copy of the module that prints its input), from the suite at *c*'s
parent and the suite at *c* together. In Config Validator the instantiation is the whole
constraint object the test supplies, and the subject is the asset.

**The witness space.** The exact study's construction from the guards of *P* and *F* together,
per instantiation, under its cap of 250,000 cells, checked as that study checks it: 200 inputs
drawn by perturbing cells, the authors' own inputs from both suites, and 200 perturbations of
those; an input on which *P* and *F* differ while no cell separates them is a missing cell, and
the fault is excluded. For Config Validator, the analysis that builds the space reads the
module with `input.asset` as the subject and `input.constraint` as the instantiation, renamed to
the exact study's `input.review` and `input.parameters`; every decision is taken on the original
module. The engine is OPA 1.20.2 with `--v0-compatible`; every decision of *P* and *F* on every
cell is OPA's (`violation` in Gatekeeper, `deny` in Config Validator).

**Eligibility.** Both versions compile; the paper's membership procedure
(`scripts/fragment_membership_rego.py`, run on the corpus as it stood at each version's commit)
judges each version inside the fragment or a policy schema, which the suites instantiate as the
exact study's secondary population is instantiated, and nothing else; the witness space is
built under the cap and passes the check; and *P* and *F* decide differently on some cell under
some instantiation. A fault failing any of these
is excluded by name with the reason; one where the two versions agree everywhere is reported as
*no decision change under the tested settings*.

**The strategies.** The payoff study's five, with *P* as the policy: one witness per cell of the
common refinement of *P* and *F*; one per class of *P*'s quotient, built from *P*'s atoms as the
Rego payoff study builds it, the decision of *P* checked constant on every class; one per
decision *P* makes; and random suites of those two sizes, drawn uniformly from the cells. The
exposure probability of each is computed in closed form, as in the payoff study, with the
single "mutant" *F*.

## Outcomes

**Primary.**
1. The share of eligible faults whose difference set is a union of *P*'s quotient classes, so
   that one witness per class exposes the fault with certainty, against those whose difference
   set splits a class, where it exposes the fault only by chance. This is the answer to whether
   real faults behave like the operators' mutants.
2. The mean exposure probability of each strategy over the eligible faults, and the paired
   comparisons **H1** (quotient > random suite of the same size) and **H2** (quotient >
   decision proxy): bootstrap 95% intervals and sign-flip permutation tests with 10,000
   resamples at seed 20261004, Holm's correction over the two, wins, ties and losses.

**Secondary.** The same by corpus; whether *F* reads a path *P* does not read; and each fault's
cells, classes, decisions and difference set, reported by name. Faults that share a commit are
reported as such.

## The candidates

| # | Corpus | Commit | Module | Class | Reason |
|---|---|---|---|---|---|
| 1 | gatekeeper | `c63556745c` | `src/general/disallowedtags/src.rego` | behaviour fix | a registry port no longer counts as an image tag |
| 2 | gatekeeper | `4416aa12b4` | `src/pod-security-policy/proc-mount/src.rego` | behaviour fix | empty procMount values allowed |
| 3 | gatekeeper | `ee2e26edb6` | `src/general/disallowanonymous/src.rego` | behaviour fix | missing allowedRoles defaults to none |
| 4 | gatekeeper | `eba78be3d8` | `src/pod-security-policy/selinux/src.rego` | excluded | message |
| 5 | gatekeeper | `4fcc6ea06b` | `src/pod-security-policy/forbidden-sysctls/src.rego` | excluded | message |
| 6 | gatekeeper | `1c6d510c5a` | `src/pod-security-policy/proc-mount/src.rego` | behaviour fix | adds a parameter check to the proc-mount rule |
| 7 | gatekeeper | `f474791644` | `src/general/replicalimits/src.rego` | excluded | message |
| 8 | gatekeeper | `2e41e9869d` | `src/general/poddisruptionbudget/src.rego` | behaviour fix | subset match of selector labels |
| 9 | gatekeeper | `55c0ac6590` | `src/general/storageclass/src.rego` | behaviour fix | absent inventory handled |
| 10 | gatekeeper | `749ebacafb` | `src/general/uniqueserviceselector/src.rego` | behaviour fix | compares Services only |
| 11 | gatekeeper | `3f73cca324` | `src/pod-security-policy/host-filesystem/src.rego` | behaviour fix | the root path / handled |
| 12 | gatekeeper | `a4273fe2e0` | `src/pod-security-policy/users/src.rego` | behaviour fix | a false security-context field counts as present |
| 13 | gcp | `4a2abc7415` | `validator/network_enable_flow_logs.rego` | behaviour fix | exceptions by subnet purpose |
| 14 | gcp | `60e457c8ec` | `validator/network_enable_flow_logs.rego` | behaviour fix | reads logConfig.enable |
| 15 | gcp | `b6ca0f44a3` | `validator/gcp_iam_restrict_service_account_key_age.rego` | behaviour fix | far-future expiry dates |
| 16 | gcp | `c873feb9bd` | `validator/gke_restrict_pod_traffic.rego` | behaviour fix | drops an obsolete requirement |
| 17 | gcp | `117763e905` | `validator/storage_bucket_policy_only.rego` | behaviour fix | reads uniformBucketLevelAccess |
| 18 | gcp | `73fdd2fee8` | `validator/gke_dashboard.rego` | behaviour fix | default of a missing field |
| 19 | gcp | `1be3d446a4` | `validator/serviceusage_service.rego` | behaviour fix | reads the service name in the new format |
| 20 | gcp | `20914add87` | `validator/bq_dataset_location.rego` | behaviour fix | missing exemptions default to none |
| 21 | gcp | `20914add87` | `validator/sql_location.rego` | behaviour fix | missing exemptions default to none |
| 22 | gcp | `20914add87` | `validator/storage_location.rego` | behaviour fix | missing exemptions default to none |
| 23 | gcp | `b84deb6509` | `validator/iam_allowed_bindings.rego` | excluded | parameter renaming |
| 24 | gcp | `2c0e9d66e0` | `validator/gke_enable_alias_ip_ranges.rego` | behaviour fix | a missing ipAllocationPolicy handled |
| 25 | gcp | `816da89604` | `validator/network_restrict_default.rego` | excluded | comments |
| 26 | gcp | `07e9da23f2` | `validator/gke_restrict_client_auth_methods.rego` | behaviour fix | safe defaults after version 1.12 |
| 27 | gcp | `4e070db149` | `validator/bigquery_dataset_world_readable.rego` | behaviour fix | the world-readable check restored |
| 28 | gcp | `ef2e3ef1a4` | `validator/gcp_lb_forwarding_rules_whitelist.rego` | behaviour fix | reads renamed fields |
| 29 | gcp | `8ae5c82ca2` | `validator/compute_network_interface_whitelist.rego` | behaviour fix | reads renamed fields |
| 30 | gcp | `4d8371535f` | `validator/bigquery_dataset_world_readable.rego` | behaviour fix | restructured world-readable checks |
| 31 | gcp | `fd44aac478` | `validator/restricted_firewall_rules.rego` | excluded | formatting |
| 32 | gcp | `c218d84406` | `validator/restricted_firewall_rules.rego` | excluded | formatting |
| 33 | gcp | `7221a5ea22` | `validator/network_enable_flow_logs.rego` | behaviour fix | a missing enableFlowLogs handled |
| 34 | gcp | `0f5a5d99a7` | `validator/gke_disable_legacy_endpoints.rego` | behaviour fix | inverted condition |
| 35 | gcp | `b9318add3e` | `validator/sql_backup.rego` | behaviour fix | wrong comparison operator |
| 36 | gcp | `0384a119cb` | `validator/sql_maintenance_window.rego` | excluded | formatting |
| 37 | gcp | `1987d4f0f6` | `validator/sql_maintenance_window.rego` | behaviour fix | rule logic |
| 38 | gcp | `7cf6fd15b4` | `validator/gke_cluster_location.rego` | excluded | copyright |
| 39 | gcp | `b8ebaa6ee3` | `validator/gke_cluster_location.rego` | excluded | message |
| 40 | gcp | `a98af1a657` | `validator/sql_allowed_authorized_networks.rego` | excluded | package renaming |
| 41 | gcp | `3924e1d48d` | `validator/vm_external_ip.rego` | behaviour fix | reads renamed fields |
| 42 | gcp | `26279aba08` | `validator/sql_ssl.rego` | excluded | copyright |
| 43 | gcp | `5cedf1ecb7` | `validator/sql_ssl.rego` | behaviour fix | reads the new data format |
| 44 | gcp | `c6cb4252d8` | `validator/enforce_labels.rego` | excluded | formatting |
| 45 | gcp | `5109209ea4` | `validator/enforce_labels.rego` | behaviour fix | false positives on non-standard types |
| 46 | gcp | `89c8308501` | `validator/sql_location.rego` | excluded | message |
| 47 | gcp | `f5be4cc4b7` | `validator/gcp_iam_restrict_service_account_creation.rego` | excluded | formatting |
| 48 | gcp | `505fc0eb14` | `validator/compute_zone.rego` | excluded | copyright |
| 49 | gcp | `e8b778ea91` | `validator/compute_zone.rego` | excluded | parameter renaming |
| 50 | gcp | `30ac44b907` | `validator/bq_dataset_location.rego` | excluded | comments |
| 51 | gcp | `de34593780` | `validator/gcp_iam_restrict_service_account_creation.rego` | behaviour fix | asset type string |
| 52 | gcp | `caff5d120e` | `validator/storage_bucket_world_readable.rego` | behaviour fix | asset type string |
| 53 | gcp | `83e7939770` | `validator/compute_zone.rego` | excluded | copyright |
| 54 | gcp | `f71f9b2d5a` | `validator/compute_zone.rego` | excluded | parameter renaming |
| 55 | gcp | `51db860acc` | `validator/cmek_rotation.rego` | excluded | message |
| 56 | gcp | `816f95c498` | `validator/glb_external_ip.rego` | excluded | message |
| 57 | gcp | `3897dc5068` | `validator/sql_public_ip.rego` | excluded | package renaming |
| 58 | gcp | `6b813641a0` | `validator/sql_ssl.rego` | excluded | message |
| 59 | redhat | `255c952b46` | `policy/ocp/bestpractices/pod_antiaffinity_notset/src.rego` | excluded | lint |
| 60 | redhat | `f965ad1730` | `policy/ocp/bestpractices/container_livenessprobe_notset/src.rego` | excluded | links |
| 61 | redhat | `f965ad1730` | `policy/ocp/bestpractices/container_readinessprobe_notset/src.rego` | excluded | links |
| 62 | redhat | `f965ad1730` | `policy/ocp/deprecated/ocp4_3/buildconfig_jenkinspipeline_strategy/src.rego` | excluded | links |
| 63 | redhat | `8fa2ebf68b` | `policy/ocp/bestpractices/container-image-unknownregistries/src.rego` | behaviour fix | only external registries |
| 64 | redhat | `0e4394208d` | `policy/ocp/bestpractices/container-image-unknownregistries/src.rego` | excluded | style |
| 65 | redhat | `0e4394208d` | `policy/ocp/bestpractices/container-resources-memoryunit-incorrect/src.rego` | excluded | style |
| 66 | redhat | `905fd90427` | `policy/ocp/bestpractices/container-resources-limits-cpu-set/src.rego` | excluded | links |
| 67 | redhat | `fc765afae0` | `policy/ocp/bestpractices/container-liveness-readinessprobe-equal/src.rego` | excluded | lint |
| 68 | redhat | `5132d8b8b0` | `policy/ocp/bestpractices/pod-antiaffinity-notset/src.rego` | behaviour fix | reads the pod spec where it is |
| 69 | redhat | `cf99fcedfd` | `policy/ocp/bestpractices/container-secret-mounted-envs/src.rego` | excluded | message |
| 70 | redhat | `aea815790c` | `policy/ocp/deprecated/4_2/catalogsourceconfigs-v1/src.rego` | behaviour fix | a kind check added |
| 71 | redhat | `aea815790c` | `policy/ocp/deprecated/4_2/catalogsourceconfigs-v2/src.rego` | behaviour fix | a kind check added |
| 72 | redhat | `aea815790c` | `policy/ocp/deprecated/4_2/operatorsources-v1/src.rego` | behaviour fix | a kind check added |
