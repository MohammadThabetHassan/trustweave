# Changelog

All notable changes to TrustWeave are documented in this file. The project follows a keep-a-changelog style and uses semantic versioning for authorized releases.

## [0.3.1] - Unreleased release candidate

### Added

- `scripts/clone_pinned_corpora.py` puts every corpus on disk at the commit its artifact
  records, deriving the list from the artifacts so it cannot drift from the measurement, and
  refuses a checkout that did not finish. A blobless clone fetches file contents lazily and a
  partial checkout still answers `git rev-parse HEAD` correctly, which is how one measurement
  came to read a fifth of its repository and record the commit for all of it; re-running now
  repairs such a tree rather than only reporting on it.
- `.github/workflows/provenance.yml` runs that reproduction monthly and on request: it clones
  all eleven pinned repositories, installs a digest-verified `opa`, re-measures, and fails if
  any count differs from the committed artifact. It is deliberately not on push, because it
  fetches roughly 700 MB from third-party repositories. Every other check in this repository
  compares the artifacts with themselves, which cannot catch an artifact recording a commit
  that does not describe what was read.
- `docs/REPRODUCING_THE_STUDY.md` is the guide an artifact reviewer needs: what to install,
  how to re-derive each artifact, what should match, why the manuscript is in a separate
  private repository, and the four things this repository cannot check on its own. Named to
  avoid collision with `docs/REPRODUCIBILITY.md`, which is about the tool's own deterministic
  output; the two now cross-link.
- The manuscript guard checks figure data. A plotted series lives in
  `\addplot coordinates {...}` and no prose pin reaches it, so coordinates can go stale while
  the caption, the surrounding text and the artifact all still agree. Each series is now
  recomputed from its artifact and reported by name when it disagrees, and a figure whose
  label moves is reported rather than silently skipped.
- `scripts/azure_initiative_bindings.py` and
  `docs/azure-initiative-bindings-v1.json` answer, from the corpus, whether the
  instantiation a schema verdict presumes actually exists: 538 of the 769 Azure schemas are
  included in a built-in initiative that binds every parameter they left without a default,
  and 231 are in no initiative that binds anything. The 538 had been a hand count quoted
  beside a denominator a re-measurement moved, and the completeness half of the claim --
  that the initiative binds the parameters that had no default, rather than some other
  parameter -- had never been checked at all.
- `scripts/verify_corpus_provenance.py` re-measures every whole-corpus membership
  artifact from the commits it records and diffs the counts, so the claim that a figure
  reproduces is an instrument rather than a note. Its last run is
  `docs/corpus-provenance-verification-v1.json`: 7 of 11 artifacts re-measured and all 7
  reproduced, with a stated reason for each of the four it does not check. It takes the
  corpora as an input rather than cloning them, so it needs no network and cannot depend on
  a remote still serving a commit. The Azure discrepancy below is what it was written for.
- The copy of an Azure definition that gets judged is now chosen rather than inherited from
  the filesystem. 25 identifiers appear at two paths in the pinned tree and 7 of those pairs
  state different rules, so keying on the identifier and keeping the first path visited
  decides a verdict; `CANONICAL_DIRECTORIES` makes the published built-in win instead of
  whichever path sorted first. The verdicts are unchanged, which is the point: the choice was
  already being made, just not by anyone.
- `scripts/oracle_rego.py` and `docs/oracle-rego-v1.json`: the Rego membership instrument
  checked against `opa deps` on all 273 measured modules, static and — for the 23 Gatekeeper
  templates that ship a suite and that the adapter calls inside — dynamic, running each
  suite as shipped and under two injected `data` documents standing for cluster state the
  policy did not write. 230 tests give the same outcome either way. The artifact records
  what the engine flags that the hand list lacked and what each corpus calls.
- `scripts/interpreter_oracle.py` and `docs/interpreter-oracle-v1.json`: the harness's
  decision map against `evaluate_flow`, with the seed, the policies, the counts and the
  disagreements — listed rather than counted, so that a future one names a policy and a
  subject.
- `trustweave discover` statically analyzes local Python source for the tool surface an
  agent can reach, proposes an action class per tool from a versioned symbol catalog with
  the evidence that produced it, reports declaration drift in both directions against a
  supplied manifest, and emits a declaration-coverage figure. Trust is always emitted as
  `unknown`; the analyzer never infers it. Recorded in ADR-0006, which narrows the
  previously published boundary on repository analysis.
- `trustweave.dev/code-discovery/v1alpha1` artifact contract and schema.
- Ten `TW-CODE-*` review rules covering refusal, drift, and declaration mismatch.
- `discover` recognises the registration forms agents actually use: Semantic Kernel plugin
  methods, LangChain `BaseTool` subclasses whose behaviour sits in `_run` or `_arun`, and
  the names a low-level MCP server declares in `list_tools` and implements in one
  `call_tool` handler. Every tool in the classification benchmark is now discovered.
- Tools whose registered name differs from the function that implements them record both.
  A factory can expose `object_summary` while the code that runs is
  `summarize_bucket_object`; the artifact carries an `implementation` field and the report
  prints it under the registered name.
- `docs/classifier-evaluation-v1.json` records the benchmark result, broken down by
  registration form and refusal reason, and a ratchet in the test suite holds accuracy,
  precision when answering, tools discovered, and per-class recall against it.
- Added versioned evaluation governance, a deterministic twelve-case synthetic corpus, local preflight validation, corpus lifecycle controls, reviewer quickstart, archive-readiness materials, and safe public-feedback/triage infrastructure. These are prepared repository-controlled foundations; no independent reviewer, pilot, adoption, benchmark, archive, or security-efficacy result is claimed.
- Added an owner-facing GitHub governance decision record, a manually triggered least-privilege OpenSSF Scorecard assessment workflow that retains a local GitHub Actions artifact without publishing results, and a record template that prohibits score, badge, certification, or remediation claims before owner-reviewed evidence exists.
- Added a fixed offline reviewer packet, consent-aware feedback and result-record templates, and a deterministic local artifact builder/verifier that allowlists public-safe files, records SHA-256 digests, rejects unsafe paths and credential-like content, and creates deterministic local ZIP packages without upload or network behavior.

### Changed

- The research write-ups moved out of the repository. A journal, and the similarity check
  it runs, reads a publicly posted full text as prior dissemination, and that applies to
  the long-form development as much as to the manuscript — including a prospectus that was
  published on the docs site complete with the claim, the theorem statements, and the
  measured figures. Every measurement artifact under `docs/` stays, each recording the
  corpus commit it read, along with every instrument in `scripts/` that produced one.
  `docs/site/RESEARCH_NOTE.md` says where the write-ups went and how to point the two
  checks that read them at their new location.
- `demo/research-assistant/demo.gif` is re-encoded from 1,345 KiB to 892 KiB with the same
  44 frames, the same dimensions and the same per-frame timing. It is a recording of a real
  run and is not regenerable from anything in this repository, so nothing was re-rendered:
  `scripts/optimise_demo_gif.py` reads the frames that are there, quantises them to a
  16-colour palette — the source holds 48 distinct colours, and 64 or 128 produce identical
  output — and verifies that the count, size and timing survive. The reason it had grown to
  more than twice what any case is allowed is that it had no budget and nothing measured it,
  so `tests/test_demo_gif_budget.py` now holds it to 1,000 KiB and fails if any future GIF
  appears in a directory no budget covers. The budget says how large a file may be; a
  second check says how it got there, holding every demo GIF to its renderer's palette
  width — 16 colours here, 64 for a case — read from the GIF's own colour tables rather
  than through Pillow, which is an optional extra the CI environment does not install.
  Every frame's local table is checked too, since a wide local palette would otherwise
  defeat a narrow global one without changing a byte of the header.
- The declaration-consistency case walkthroughs no longer print
  `== Captured terminal output begins ==` into the terminal body. Distinguishing what
  `run-case.sh` emitted from what the renderer added is worth keeping, so captured lines
  now carry a rule down the left margin and one caption at the foot instead of two lines
  of narration. The briefing dropped from seven labelled fields to the three a reviewer
  needs, output advances two lines at a time rather than four, and the canvas follows the
  content instead of leaving a third of the terminal empty. A 64-colour palette pays for
  the extra frames: the largest case is 523 KiB against the 600 KiB budget, smaller than
  before with two thirds more frames.

- Separated the prepared source version from the last observed public package release in the compatibility contract so an unreleased candidate cannot be presented as published provenance evidence.
- Replaced fragile README release-version prose with durable PyPI and GitHub Releases references while retaining the exact historical `0.3.0` release-evidence limit.
- Rewrote the README around a verified two-minute quickstart with real output, a curated docs index, and a shorter plain-language explanation of the evidence-not-enforcement boundary.
- Reorganized documentation: point-in-time release checklists, migration guides, audit records, and the maintainer handoff snapshot moved to `docs/archive/` with an index; ADRs moved to `docs/adr/`; the documentation site navigation is grouped by task (getting started, concepts, how-to, CLI, policies, assurance, releases).
- Tightened the installation and troubleshooting pages, fixed stray code-block indentation, and made the missing-paths configuration error list exactly which paths it wants.
- The mutation quality and survivor-parity gate moved out of an inline workflow script into
  `scripts/mutation_gate.py`. The hosted job now invokes the same script a contributor can
  run before pushing, which is what the previous arrangement made impossible.
- The mutation scope covers sixteen modules; `code_sources.py` and `code_discovery.py`, the
  intake and artifact production behind `trustweave discover`, are gated with the rest.
- The mutation run now covers two scopes with two contracts. Sixteen modules are gated: a
  95% threshold computed over that scope alone, exact survivor parity, a recorded proof for
  every survivor, and no mutant without a covering test. `code_analysis.py` is ratcheted: it
  is mutated on every run and held to a floor in `docs/mutation-ratchet-v1.json` that it may
  not fall below. It is not gated because the triage would need a proof for each of its 353
  survivors and most are not equivalences, but leaving it out of the run entirely meant its
  rate could fall with nothing to say so.
- A mutant reported as having no covering test is forbidden in the gated scope, where the
  triage cannot account for it, and counted in the denominator of a ratcheted module, so
  unreachable code lowers the rate rather than hiding in it. That accounting found the
  call-depth fail-open fix had no test protecting it.
- `scripts/fragment_membership.py` measures which published policies lie inside the
  decidable fragment, one adapter per ecosystem: 15 of 21 XACML policies, 41 of 49 Kyverno
  policies, and 22 of 22 Cedar policies, with nothing left undetermined in any of the
  three. It replaces the XACML-only `scripts/xacml_fragment_membership.py`.

### Fixed

- The Azure measurement did not reproduce from the commit it recorded. Re-cloning
  `Azure/azure-policy` at the pinned `9780ba64` and re-running the adapter found 3,769
  definitions where the committed artifact recorded 3,659. The commit was right; the
  working tree was not — only `built-in-policies/` had been materialised, a blobless clone
  whose checkout did not finish, so the adapter walked a fifth of the repository while the
  artifact recorded a commit describing all of it. We first published the wrong diagnosis,
  having inferred from the file counts that an older tree had been measured; the missing
  subject set is exactly the `built-in-policies` subtree at that same commit, which the
  inference did not fit. Every Azure figure is re-measured at the pin, and the other seven
  corpora were re-cloned and re-measured the same way: all seven reproduce their committed
  artifacts exactly. Each artifact now records `tracked_files` and `files_present` per
  repository, so an incomplete checkout is visible in the measurement's own artifact rather
  than only in a later re-run. Two definitions that had been undetermined are judged —
  `true()` and `false()` are constants, and `claims()` reads a value projected from a
  Resource Graph query the definition declares and the platform runs across the tenant,
  which is the same obstruction as Kyverno's `context.apiCall`.

- Two guard regions were read wrongly and one was not read at all, which is the largest
  correction in this release. A definition's decision is made by `policyRule.if` and, for
  the `AuditIfNotExists` and `DeployIfNotExists` effects, by
  `then.details.existenceCondition`; `then.details.deployment` is the remediation template
  and runs after the decision. The adapter read leaf operators from `if` while scanning the
  *whole* rule for template functions, so 96 of 99 exclusions for reading another resource's
  runtime state were `reference()` calls inside a remediation template, and the existence
  condition — the deciding guard of 1,330 definitions — was never read. 651 definitions were
  reported inside on a guard the instrument had not looked at. An existence test over a
  related resource is outside the fragment for the same reason Gatekeeper's injected
  inventory is: the evaluator fetches those resources after `if` matches, and they are not in
  the request the decision is about. 1,444 definitions decide that way, and the Azure row is
  2,150 of 3,769 inside rather than the 2,884 the re-measurement alone had produced.
- 57 Azure definitions are declined rather than judged, and they are the study's first
  refusals. Azure Policy for Kubernetes states no condition tree: `then.details.templateInfo`
  names a Gatekeeper ConstraintTemplate — a Rego program — at an HTTPS URL, so the guard is
  not in the artifact and an offline procedure has nothing to read. 43 of the 57 had been
  reported inside because the part that could be read contained nothing alarming. The
  program's location is recorded, so the refusal can be lifted by fetching rather than by
  re-deriving anything, and the parameter evidence is recorded for them too.
- XACML was selected by filename — `TestPolicy_*.xml` or `Policy.xml` — which is not a
  property of a document and was deciding the corpus. 459 policies were left out, among them
  every one that reads the clock. Selection is by root element now, subjects are named by
  path rather than by directory (naming them by directory collapsed 1,007 documents to 539),
  and `environment:current-time` and its siblings are recognised, so the 15 clock readers
  land in the same taxonomy row as Azure's `utcNow` and Rego's `time.now_ns`.
- Kyverno's external-context test asked whether the string `configMap` occurred anywhere in
  the file, which is true of a description sentence, of a CEL read of
  `object.spec.volumes.configMap`, and of a payload injecting `configMapRef`. It reads the
  parsed document now, walking every `context` list wherever it sits — including inside a
  `foreach`, which a first attempt missed and which would have turned five image-registry
  policies into false negatives. `namespaceSelector` is recognised: the AdmissionReview
  carries the namespace's name, not its labels.
- The taxonomy counts over every obstruction an artifact carries rather than the one the
  verdict reports. The reported reason is the one that survives instantiation, so the size of
  the "not a policy" row was depending on which other obstruction outranked it — it would
  have moved by 749 Azure definitions when a second guard region was read, without one
  artifact changing its schema status. Reporting and counting are now separate questions.

  **Pooled across the eight corpora, and authoritative for this release:** 7,006 artifacts;
  902 policy schemas; 5,186 of the 6,104 artifacts that are policies inside the fragment
  (85.0%); 1,763 exclusions (902 / 841 / 20); 57 declined.
- A clock read was two different kinds of exclusion depending on the language. The Azure
  adapter pooled `utcNow()` and `newGuid()` with `reference()`, so a definition reading the
  clock was reported as reading another resource's runtime state, while the Rego adapter
  reported `time.now_ns` as evaluation-time state; the pooled taxonomy therefore carried
  one obstruction under two headings. The two adapters now share one reporting rule — the
  obstruction that survives instantiation is the one named, so nondeterminism outranks
  reading outside state, which outranks being a schema — and each records every obstruction
  it found rather than only the one that won, so a clock read is one row of the taxonomy in
  every language. The pooled totals this fix produced were superseded within this same
  release cycle by the Azure guard-region correction; the authoritative totals are recorded
  with it.
- Azure definitions excluded for reading runtime state did not record their undefaulted
  parameters, because the classifier returned before it looked, so the count of definitions
  awaiting an assignment could not be derived from the artifact it was quoted beside. The
  evidence is recorded unconditionally now: 855 definitions have a parameter with no
  default, of which 769 are reported as schemas and 86 carry a stronger obstruction as well.
- The coverage-cost measurement walked (name, path) pairs where the membership measurement
  keys on the name, so seven Azure definitions were measured twice and the cost denominator
  was larger than the inside set it described. It measures each definition once, at the path
  the verdict was reached on, and fails loudly if the two ever disagree again.
- The interpreter oracle skipped any generated policy whose quotient exceeded 4,000 classes,
  which silently biased the check towards small quotients: 132 candidates were dropped. The
  cap is an argument now, its default is 200,000, and the sizes of what it excludes are
  recorded. One candidate of 201 is skipped, at 414,720 classes, and the check covers
  1,702,668 class witnesses rather than 223,452 — still with no disagreement.

- The Rego fragment-membership adapter was checked against the engine that runs the
  policies, and four verdicts changed. `opa deps` reports the base documents a package's
  rules depend on from OPA's own compiler; `scripts/oracle_rego.py` puts every module of
  both Rego corpora to it and to the adapter and requires the two readings to agree. On the
  first run they did not. A published module calls `http.send(request, response)` as a
  top-level statement, which in the AST is a bare list of terms rather than a `call` node,
  and the walker looked for the wrapped form alone — it was recorded inside the fragment.
  The five nondeterministic builtins the adapter listed by hand are a strict subset of the
  nine the engine flags; the set now comes from `opa capabilities`. Propagating exclusions
  along imports rather than along the rules a policy evaluates was wrong in both directions:
  one `redhat-cop` policy imports `lib.openshift` and calls only a request-reading rule of
  it, and was excluded; one `opa-library` policy reaches cluster state through a package
  prefix indexed by a variable, and was not. And a ref's later `var` parts were read as
  static keys, so `vetter[_].info[r]` resolved to nothing. The four-corpus artifact moves
  from 116 inside of 186 to 115, with 24 rather than 25 excluded through a library rule.
- Google's Config Validator templates take Constraint parameters through
  `input.constraint`, not Gatekeeper's `input.parameters`, and the adapter knew only the
  second convention. The same construct that made 28 Gatekeeper templates policy schemas
  was counted as policy in Google's library, which reported 85 of 87 inside. The criterion
  is now stated once and applied to both: an artifact is a schema when it reads a
  parameter the policy supplies no default for, where `object.get` and Config Validator's
  `lib.get_default` with a literal default are defaults, exactly as an Azure `defaultValue`
  is. Google's library is 31 schemas, 15 templates complete by their own defaults, 39 that
  read no parameter and 2 that read the clock: 54 of 87 inside. The corpus ships a sample
  Constraint instantiating every one of the 31, and the test that checks that claim now
  runs against both corpora.
- The decision map `scripts/policy_mutation.py` builds was checked against the engine that
  ships, and two defects the shipped policy never reaches were found and fixed. The theory
  tests' "engine's own first-match evaluation" had called the harness's re-implementation;
  `scripts/interpreter_oracle.py` decides every class witness and a seeded sample of
  concrete subjects through `trustweave.engine.evaluate_flow` as well, over the shipped
  policy, a richer variant and 200 generated policies the parser accepts. `abstract_cell`
  collected every witness a subject's capabilities matched where the enumeration keeps one
  representative per achievable signature, so under nested patterns a subject was placed on
  a cell no decision map contained; it is placed by signature now. And the witness space had
  no value for a classification outside the taxonomy, which the engine admits and which
  fails every bound, so such a subject was placed on the first taxonomy entry and decided
  wrongly; the outsider is a class of its own now. After both fixes the two agree on 223,452
  class witnesses and 8,080 sampled subjects. The theory test decides through the engine.
- The exclusion taxonomy's third row was named for the clock alone. The network call the
  oracle found belongs to the same kind — state that does not exist until evaluation, which
  no choice of subject fixes — so the row is "reads evaluation-time state" and holds three.
- The manuscript guard's own perturbation tests carried figures by hand — a pooled count
  summed over four ecosystems from before IAM and Azure joined the table, and mechanism
  counts from before the worked example was corrected — and so could not run where the
  manuscript lives. They derive their figures from the artifacts and the paper now, and the
  guard pins 68 claims rather than 51.
- The repository reality check read `<https://example.com>` — the angle-bracketed form
  Markdown permits — as a broken local path. Nineteen valid DOI links were reported as
  broken once a generated report used that form. The brackets are delimiters and are now
  stripped before the scheme is tested.

- Effects that were reachable but unreported, each of which had the analyzer describe a
  tool as harmless when it was not: a symbol called through a local alias, a method on an
  instance the tool constructs, a sibling method reached through `self`, a client used
  behind an attribute chain, a receiver handed to a helper, a credential path assembled by
  `/` composition, and a literal argument the deciding call sees one frame up. Constructing
  the object a protocol requires a tool to return no longer suppresses an observed effect.
- An observed effect at the top of the precedence order is reported even when something
  else in the same tool could not be resolved, since nothing outranks it. Below that class
  the refusal stands.
- The published mutation record and the survivor-triage inventory it describes stated
  different totals -- 126 survivors of 6,691 mutants in the prose against 133 of 6,566 in
  the inventory -- because nothing compared them. The repository-reality check now derives
  every countable claim in the record from the inventory, so a regenerated inventory forces
  the prose to be regenerated with it.
- `collect_python_sources` reported a stat failure and a read failure through messages no
  test asserted, and read sources with an encoding a mutation could drop in favour of the
  platform locale, which on a POSIX or ASCII locale records a valid UTF-8 module as
  `file_is_not_utf8`. All three are asserted now, and the stat path is no longer marked
  `# pragma: no cover`.
- Reading a credential file was reported as a benign read, at high confidence, in two of
  the four ways an agent can write it. Through the builtin `open`, because that path
  decided from the file mode alone and never consulted the credential-path table. And
  through a `pathlib.Path` stored on `self` in `__init__`, because indexing a class kept
  only the constructor's callee and discarded the literal that says the path is a secret.
  The local-variable and inline spellings were already correct, so the same operation was
  classified two different ways depending on style. All four now agree, and a test asserts
  that they do. Writes keep the write class whatever the path, matching the existing
  treatment of the pathlib write methods.
- Removed `_env_is_secret`, which was defined, never called, and fully superseded by
  `_environ_class`. It was found by the mutation gate's coverage accounting rather than by
  a failing test: eighteen of its mutants were reported as having no covering test at all,
  which is what an uncalled function looks like.
- An action class the precedence order does not contain was reported as `read`, the most
  benign class, instead of being refused. Signals are built from the catalogue, so that
  state means the analyzer produced evidence it cannot interpret, and answering benignly
  there is the one direction a security review must not fail in. A tool with no signals at
  all is a different case and still reads as `read`.
- An effect one frame past the call-depth budget was reported as a local read at high
  confidence, with `budget_state` still `complete` and no reason recorded, so an outbound
  call four frames down published as no effect at all. The breadth budget had always
  reported itself; the depth budget now does the same, and such a tool is refused rather
  than answered.
- Four more effects that were reported as benign reads, each found by working the
  classification benchmark's own failures. A receiver stored on `self` and reached through
  an attribute chain, which is how every LLM and cloud SDK is written, so
  `self.client.chat.completions.create(...)` published as a local read. An attribute taken
  from a constructor, as in `self.chat = Chat(...).chat`, which was recorded as neither a
  receiver nor a usable alias. A module-level singleton aliased to a local, which is how a
  shared handle is normally reached. And `os.environ["DB_PASSWORD"]`: the traversal looked
  only at call nodes, so the most ordinary spelling of reading a secret from the
  environment was not seen at all, while `os.environ.get(...)` and `os.getenv(...)` both
  were.
- A tool whose body only raises `NotImplementedError` is refused as `BODY_UNAVAILABLE`
  rather than classified. Its real routine is bound elsewhere, so having no effect in this
  file is not evidence of having none.
- A credential store reached through its backend was not recognised.
  `keyring.get_password(...)` was catalogued but `keyring.get_keyring()` followed by
  `backend.get_password(...)`, which is the form the library documents, was not. A
  credential store is now a receiver in the same way a network client is, so the class
  travels from the constructor through a local, an attribute chain, or an attribute stored
  on `self`.
- A file mode bound to a local was refused as though the caller supplied it. `mode = "w"`
  then `open(path, mode)` now resolves, and so does a conditional whose arms are both
  literals, since `"a" if event else "a+"` can only ever be an append. Where the arms
  disagree, or the name is rebound, or the value comes from a parameter, the refusal
  stands.
- A method called on the result of another call could not be resolved, so the analyzer
  refused on callees it could have named. A `pathlib` chain now keeps its receiver through
  each link, so `Path(p).expanduser().resolve().stat()` is one read of one path and the
  credential rule survives the chain. A method on a computed value -- `json.dumps(body)
  .encode(...)`, `hashlib.new(algo, data).hexdigest()` -- is not an effect. A database
  handle is plumbing, so `connect(dsn).cursor()` no longer poisons every database tool,
  and the statement given to `execute` decides the class as before.
- A SQL statement or file mode held in a module-level constant is resolved rather than
  treated as built at runtime.
- `eval` and `exec` applied to a caller-supplied argument are classified `sensitive`
  rather than refused. They sat with `getattr` under dynamic dispatch, but `getattr`
  selects a symbol while `eval` runs whatever it is handed: arbitrary code execution is
  what `sensitive` means here, and it is knowable without reading the code. A constant
  expression is left alone and `getattr` keeps its refusal.
- Benchmark accuracy rises from 0.806 to 0.987 over the session on a benchmark that grew
  from 72 cases to 75, the answer rate on decidable cases from 0.860 to 1.000, and
  precision when answering from 0.918 to 0.9833. Accuracy on labels the two annotators
  agree about is 1.000; the single remaining failure is the one case where they disagree.
- Two whole registration forms were unrecognised, found by running discovery over agent
  repositories with no connection to this project rather than over the benchmark. The
  OpenAI Agents SDK's `@function_tool` was recognised by nothing, so 328 tools in one
  repository were absent from the artifact rather than refused. CrewAI's `BaseTool`
  subclasses were not recognised either and its decorator fell into the generic
  `@<server>.tool()` bucket, so a repository reporting 75 tools -- every one of them `read`
  at high confidence -- actually exposes 207, of which 16 are sensitive and 11 external.
- `name_override=`, the OpenAI Agents SDK's spelling, is read as the registered name.
  Reporting the Python function's name for a tool the model is shown under another is a
  drift finding about nothing.
- The framework recorded for a class-based tool names the project its base came from, so a
  CrewAI tool is no longer reported as a LangChain one. The published
  `langchain_base_tool_subclass` label is unchanged.
- A third registration form was invisible: pydantic-ai's `@agent.tool_plain`, which does
  not end in `.tool` and so missed the receiver-decorator rule. It is used 693 times in
  that project's own repository, and none of those tools was reported. Hugging Face
  smolagents is named as itself rather than reported as an unidentifiable receiver.
- `scripts/wild_discovery_survey.py` records what discovery finds in third-party code, at
  pinned commits: 1,998 tools across nine corpora from six projects, exercising all eleven
  registration forms the documentation lists. It measures coverage rather than correctness,
  which is the failure a self-authored benchmark cannot report, and it found three
  invisible registration forms within minutes of first being run.
- The survey also screens for correctness without labels: every tool classified `read`
  whose registered name begins with a verb that would be odd for one. It flags 38 of 1,998,
  and the five inspected are mock tools in test suites that return a formatted string, so
  the reads are right and the names describe intent. It is a screen for candidate misses,
  not a classification rule.
- Corrected the reading of the study's one predictive result. The blind-against-covered
  contrast on Kyverno, p = 0.043 one-sided, is confined to the eight policies that lie
  outside the decidable fragment; inside it, over the larger arm of 41 policies, the
  difference is 0.066 at p = 0.272. The pooled figure is therefore not evidence that the
  criterion tracks fault detection where the criterion is exact, and the study now says so.
  This does not touch Corollary 4, which requires cell coverage rather than the
  decision-coverage proxy being stratified.

### Release status

- Source metadata is prepared as `0.3.1`, but **`0.3.1` is not published, tagged, uploaded, or released**. The latest observed public package release remains `0.3.0` until a separately owner-authorized publication process completes and records new exact-file evidence.

## [0.3.0] - 2026-08-20

### Fixed

- Enforced semantic authenticity and complete finding coverage for current Agent Security Bundles by regenerating the expected findings from the embedded manifest and policy during validation.
- Corrected policy coverage analysis so an impossible earlier rule cannot shadow a possible later rule, and aligned typed-policy collection and text bounds with the published v1alpha2 schema.
- Introduced `trustweave.dev/bundle-diff/v1alpha3`, which records normalized policy-only changes and review signals for fail-closed-to-fail-open approval controls (`TW-DIFF-004`), default-to-allow changes (`TW-DIFF-005`), approval-control removal (`TW-DIFF-006`), approval-binding removal (`TW-DIFF-007`), less-restrictive rule decisions (`TW-DIFF-008`), required-control removal (`TW-DIFF-009`), classification-taxonomy changes (`TW-DIFF-010`), and structural rule-set or matching-boundary changes requiring human review (`TW-DIFF-011`). The structural signal does not prove that every reported change is insecure or that every possible weakening is detected.
- Repaired the risk-management quickstart with current v1alpha2 baseline and suppression examples, plus a clean-workspace command smoke regression.
- Bound TestPyPI and PyPI publication workflows to an exact annotated `v<version>` tag and immutable target SHA. Before artifact build or isolated trusted publication, the release-gate job executes exactly: formatting and lint checks, strict typing, Bandit, pytest, `reality_check`, strict documentation build, and dependency audit. CodeQL, dependency review, mutation testing, cross-Python compatibility, build reproducibility, and isolated-wheel smoke remain separate CI or release-process controls and are not claimed as release-gate steps.
- Replaced overstated local “tamper-evident” wording with explicit unsigned-statement and external-provenance limits, and made supplied-file verification the primary documented verification command.
- Replaced the Docker image’s stale hard-coded version label with a package-metadata-derived build argument that hosted CI verifies against the installed package version.
- Made `python scripts/verify_audit_remediation.py` execute an exact, fail-closed `TW-AUDIT-001` through `TW-AUDIT-010` pytest-node mapping alongside separate corrective hardening evidence, rather than relying on a broad file-only test list.

### Changed

- Regenerated deterministic golden evidence, mutation-contract snapshots, rule catalog, compatibility contracts, traceability records, and repository-reality checks for the current v1alpha3 diff output.

> Published `0.2.3` emits `trustweave.dev/bundle-diff/v1alpha2`; `0.3.0` introduces the reviewed `v1alpha3` writer. The annotated [`v0.3.0`](https://github.com/MohammadThabetHassan/trustweave/tree/v0.3.0) tag, exact-SHA release gates, TestPyPI and PyPI trusted publication, exact-file expected-repository verification, clean installations, and [GitHub Release](https://github.com/MohammadThabetHassan/trustweave/releases/tag/v0.3.0) completed successfully. See [Release Evidence 0.3.0](docs/RELEASE_EVIDENCE_0.3.0.md). The non-executing, local-only product boundary remains unchanged.

## [0.2.3] - 2026-08-19

### Added

- Added a versioned machine-readable compatibility contract, public support/deprecation policy, and deterministic validator for the package version, Python matrix, CLI surface, exit statuses, current artifact writers, and bounded historical readers.
- Added a reviewed synthetic golden evidence corpus covering complete staged CI, three framework descriptors, saved MCP metadata/profile review, trace/risk lifecycle review, declared change/SARIF review, and malformed-input refusal. The default verifier compares approved canonical digests and never refreshes snapshots implicitly.
- Added a generated threat-control-test traceability guide and source contract linking every declaration-layer threat-model row and out-of-scope risk to real source, tests, evidence, maintenance triggers, or explicit residual limits.
- Added explicit local resource-bound documentation and a fail-closed **50,000 unique-result** SARIF cardinality limit, alongside existing input-file, structural, and declared-chain budgets.
- Added temporary clean-environment distribution assurance that builds, archive-checks, and installs both the wheel and source distribution with console, module-entry, and packaged-schema checks.
- Added TestPyPI-first package-provenance controls: both trusted-publishing workflows request PyPI project attestations, and a versioned validator requires the configuration while preserving the pre-observation non-claim.

### Changed

- Extended the repository reality gate and hosted CI with golden-evidence, traceability, distribution-assurance, compatibility, and package-provenance control checks.
- Expanded the README and documentation site with task-oriented assurance navigation and release guidance that distinguishes configured attestation generation from observed authenticated package provenance.
- Bumped source metadata to `0.2.3`; published-state documentation and compatibility records now identify `0.2.3` as the current public package release.

### Release status

- `0.2.3` is published on [PyPI](https://pypi.org/project/trustweave/0.2.3/), [TestPyPI](https://test.pypi.org/project/trustweave/0.2.3/), and [GitHub Release `v0.2.3`](https://github.com/MohammadThabetHassan/trustweave/releases/tag/v0.2.3). Its exact TestPyPI and PyPI wheels passed clean-install and expected-repository provenance verification; see [the release evidence record](docs/archive/RELEASE_EVIDENCE_0.2.3.md).
- `0.2.2` remains available as the preceding public release. The non-executing, local-only boundary remains unchanged.

## [0.2.2] - 2026-08-19

### Added

- Added `python -m trustweave` as a standard module entry point alongside the installed `trustweave` console command, with source-checkout and installed-wheel regression coverage for matching version and help behavior.
- Added a task-oriented developer integration-routes page with copy-paste local examples for LangGraph-style declarations, exported OpenAI Agents descriptors, saved MCP `tools/list` snapshots, and repository CI inputs.

### Changed

- Made the README and documentation-site installation path expose both supported CLI invocations, route developers by the local input they already have, and link directly to framework, MCP, and least-privilege CI guidance.
- Updated the checked-in CI integration example to the currently reviewed immutable `actions/checkout` v7.0.1 pin.
- Extended the repository reality check to validate module-style help from an isolated installed wheel and to reject the prior stale README release wording.

### Release status

- `0.2.2` is published on [PyPI](https://pypi.org/project/trustweave/0.2.2/), validated from [TestPyPI](https://test.pypi.org/project/trustweave/0.2.2/) and PyPI clean installations, and available as [GitHub Release `v0.2.2`](https://github.com/MohammadThabetHassan/trustweave/releases/tag/v0.2.2). Its annotated tag targets `3b0817e732627a62a18be82e854a58fa085f0922`. It does not change the non-executing, local-only product boundary.

## [0.2.1] - 2026-08-19

> This corrected public release was authorized and published from annotated tag [`v0.2.1`](https://github.com/MohammadThabetHassan/trustweave/tree/v0.2.1), which targets `f1394d5fba8a0fbc24e3a18f45702e83aa65645e`. The protected trusted-publishing workflows completed successfully, and the exact package was validated from both TestPyPI and PyPI.

### Fixed

- Added top-level `trustweave --version` and `trustweave -V` commands. Both print only the authoritative import-visible package version, exit successfully without a subcommand, and do not discover configuration, write files, or access the network.
- Added source-checkout and installed-wheel regression coverage for the version contract, including exact stdout, empty stderr, package-metadata synchronization, and installed console-script behavior.
- Corrected the release procedure after the immutable `v0.2.0` pre-publication tag exposed the missing top-level version smoke command. The corrected clean-checkout staged-CI reproducibility procedure remains required and does not depend on a tracked root `trustweave.toml`.

### Release status

- `v0.2.0` targets `7232fe3a23d92f50a693903c0a6b7cb92d0a1426` and remains an immutable **unpublished audit record**. It was never published to PyPI and has no GitHub Release; it must not be moved, reused, or published from.
- `0.2.1` is published on [PyPI](https://pypi.org/project/trustweave/0.2.1/), validated on [TestPyPI](https://test.pypi.org/project/trustweave/0.2.1/), and available as [GitHub Release `v0.2.1`](https://github.com/MohammadThabetHassan/trustweave/releases/tag/v0.2.1). See [the 0.2.1 release notes](docs/archive/RELEASE_NOTES_0.2.1.md) and [completed owner release record](docs/archive/OWNER_RELEASE_CHECKLIST_0.2.1.md).

## [0.2.0] - Unpublished immutable audit record

> `v0.2.0` was created during pre-publication verification and intentionally remains unpublished. No PyPI file and no GitHub Release was created for it. The tag is retained unchanged for auditability; `0.2.1` is the corrected release target.

### Fixed

- Added strict semantic validation for historical `agent-security-bundle/v1alpha1` evidence while preserving explicitly documented safe compatibility behavior for authentic v0.1.1 local bundles. Current v1alpha2 bundle validation remains strict.
- Enforced the exact risk-decision expiry boundary: a baseline or suppression expiring at the local review timestamp is expired rather than active.
- Hardened strict risk, SARIF, chain, attestation, canonical-finding, policy, configuration, and staged-CI contracts with malformed-input, field-path, lifecycle, ordering, and provenance regressions.
- Enforced strict declared-chain node roles, removed the ambiguous `output` node kind, and applied path, state, and edge budgets before retaining limit-plus-one work in partial local analysis.
- Preserved ordered declared chain paths in risk fingerprints and deeply froze normalized risk subjects, preventing a mutable caller or a reversed path from inheriting another local decision identity.
- Unified built-in review observations behind a bounded, deeply immutable canonical finding contract. Ordered chain paths, safe integer analysis metadata, producer conformance, and published finding-schema validation now agree without permitting arbitrary nested evidence.

### Changed

- Split the command-line implementation into focused command modules behind a sub-200-line public facade, preserving stable command help and exit-code behavior with golden help contracts.
- Made the repository reality check validate real generated artifacts, exact schema resources from an installed wheel, and CLI command coverage derived from the authoritative parser.
- Centralized built-in review-rule guidance for producer validation, SARIF rule metadata, Markdown review reports, generated rule-catalog documentation, and reality-check completeness enforcement.
- Deduplicated raw review and derived risk-review SARIF results by canonical finding fingerprint while preserving every contributing local artifact location.
- Made `LocalReviewResult` recursively immutable and defensively copied so nested caller-owned review data cannot mutate public API results.
- Rejected risk baseline drafts whose expiry is not later than the supplied local review timestamp.
- Rejected unknown policy-v2 required controls outside the bounded declared-control catalog and rejected rules with an empty exact-classification and taxonomy-bound intersection.
- Preserved every distinct declared chain path during bounded traversal and scoped fail-closed approval evidence to sensitive classifications acquired before the approval node.
- Aligned generated bundle, embedded finding, and v1alpha3 attestation schemas with real runtime artifacts, and packaged public schemas for installed-wheel discovery.
- Added the immutable, data-only `trustweave.api.LocalReviewResult` wrapper for typed consumption of already-generated local review artifacts.
- Expanded `trustweave ci` into a staged local coordinator with strict typed configuration, bounded configuration discovery, selectable core review stages, atomic artifact-directory publication, deterministic summaries, `--format`, `--quiet`, `--fail-on`, optional declared-chain review, and local SARIF generation. No stage executes agents, models, tools, MCP servers, or network operations.
- Added explicit local `trustweave baseline create`, `baseline validate`, and `suppressions validate` lifecycle commands. Baseline creation requires a reviewer-provided reason and expiry and never claims remediation or authorization.
- Added strict read-only `trustweave config validate` and `config show` commands plus explicit or bounded auto-discovered `trustweave.toml` path resolution for `scan`, `test`, `policy-check`, and staged `ci` execution.
- Added opt-in `trustweave policy-check --coverage` diagnostics for first-match reachability, contradictory shadowed decisions, and impossible declared control requirements, with the same local deterministic policy boundary.
- Made declared-chain analysis stateful for propagated sensitive classifications and fail-closed approval state, and added explicit edge, depth, and state budgets to prevent unbounded local review work.
- Made flow `purpose_tags` an additive, validated manifest attribute and aligned policy-v2 matching to these machine-readable identifiers rather than the human-readable `purpose` prose, while preserving v1alpha1 manifests without tags.
- Expanded `trustweave why` with deterministic per-dimension local match evidence for every evaluated policy rule, including unbounded dimensions and declared-control checks.
- Added deterministic orphaned baseline and suppression reporting to local risk reviews so stale decisions remain visible without altering the active-finding gate or claiming remediation.
- Restored the owner-enabled SHA-pinned GitHub dependency-review action for pull-request dependency changes while retaining the independent `pip-audit` audit.
- Added a versioned bounded `trustweave.dev/policy/v1alpha2` contract with optional declared source/tool identifiers, purpose tags, classification bounds, and required declared controls, plus machine-readable `trustweave why` explanations.
- Added `trustweave chain-check` for bounded static review of explicitly supplied chain graphs and local chain-review integration with risk normalization and SARIF conversion. It reports declarations only and does not infer runtime paths.
- Added the typed, data-only `trustweave.api` public surface and repository-local composite-action, pre-commit, GitLab, and Jenkins integration assets with no default uploads or automation against external systems.

- Added an additive `trustweave.dev/finding/v1alpha1` contract for canonical local policy-review and bundle-diff entries. Stable evidence kinds and declared subjects support wording-independent local correlation while retaining existing review fields and the non-executing privacy boundary.
- Added `trustweave.dev/attestation/v1alpha3`, which binds stable payload hashes, exact file hashes, subject names, and source revision. `verify --bundle --test-results` now checks supplied local evidence bytes; readers retain `v1alpha1` and `v1alpha2` compatibility.
- Made `risk-check` schema-aware for policy, trace, MCP-profile, and bundle-diff review evidence. It now normalizes documented `findings` and diff `signals` into semantic `trustweave/fingerprint/v3` identities, preserves local input paths, and deterministically deduplicates exact identities.
- Restricted policy capability matching to exact capabilities or one final namespace wildcard, made shadow analysis conservative across classification and capability constraints, and made optional scenario attributes use the same deterministic matcher as declared manifest flows.
- Added reviewer-facing `risk-review.md` output and active-risk-only SARIF export that retains a canonical local risk fingerprint while omitting currently baselined or suppressed entries.
- Added `risk-check`, a local deterministic risk-review command that normalizes supplied review artifacts into stable fingerprints and applies explicit expiry-enforced baselines and suppressions.
- Added severity gates for active local findings, safe empty baseline/suppression templates, and maintainer guidance that distinguishes reviewer documentation from remediation or runtime enforcement.

- Added optional declarative policy constraints for exact source data classifications and bounded tool-capability globs, so those declared security attributes now affect tested flow decisions.
- Added deterministic decision severities (`high`, `medium`, and `info`) with explicit policy overrides from the documented `critical` through `info` vocabulary.
- Made manifest, policy, scenario, trace, MCP profile, MCP inventory, and supported framework-declaration parsers reject unknown declared fields by default with path-aware close-match diagnostics.
- Added schema-and-runtime conformance tests for every checked-in manifest, policy, trace, and MCP profile fixture; the repository reality check now enforces the published-schema side in CI.
- Declared `jsonschema` as a development-only conformance dependency and recorded the typed-parser authority decision in ADR-0001.
- Made generated evidence builders pure: volatile `generated_at` provenance is now injected at the CLI boundary through an explicit timestamp, `SOURCE_DATE_EPOCH`, or the local UTC clock.
- Added `trustweave.dev/attestation/v1alpha2`, whose local integrity chain covers canonical stable bundle and test-result payloads rather than volatile generation metadata. The verifier remains compatible with local `v1alpha1` statements.
- Added stable CLI exit codes for invalid input/configuration, input/output failure, and unexpected internal errors; expected failures now write concise diagnostics to stderr, while `--debug` preserves tracebacks.
- Replaced repeated-list duplicate detection in the manifest, scenario, and MCP-profile validators with linear-time counting.
- Added atomic artifact replacement and precise errors for missing files, directories supplied as files, invalid UTF-8, and output failures.
- Added PEP 561 `py.typed` package data and an isolated-wheel regression test proving the installed marker is present.

### Documentation

- Added a reproducibility and integrity contract that distinguishes deterministic decisions, stable evidence payloads, byte-identical output, volatile provenance, and unsigned local file integrity.
- Rebuilt the README as a concise developer landing page with a verified installation path, first successful local review, artifact meanings, safety boundaries, documentation map, public contribution routes, and a source-controlled product mark.
- Moved advanced workflow detail behind task-focused documentation links so the landing page remains skimmable without reducing the published command and safety contract.
- Refreshed the product contract, roadmap, release guide, security policy, governance guide, contribution guide, and TestPyPI validation guide to distinguish completed `0.1.1` release evidence from deliberate future scope.
- Added `SUPPORT.md` to route installation questions, safe bug reports, bounded feature proposals, and private vulnerability reports without promising unstaffed services.
- Added an evidence-led maturity plan that distinguishes repository-controlled 9.5+ work from external proof that must not be fabricated.
- Added a focused mutation-testing record with its Linux-only scope, exact 108-of-108 killed-mutant result, re-run procedure, and explicit non-blocking limitation.
- Added a checked-in minimal LangGraph-style project layout, provenance note, and static-import walkthrough that demonstrate a reviewable project configuration without installing, importing, compiling, or executing LangGraph code.

### Documentation

- Added a strict-build MkDocs Material documentation site with local-boundary concepts, generated parser-derived CLI help, a built-in review-rule catalog, schema catalog, and deferred authenticated-provenance design guidance.
- Added deterministic documentation freshness and strict site-build checks to the repository reality checker.

### Quality

- Completed a twelve-module mutmut measurement with **6,044 of 6,140 mutants killed (98.44%)**. The regenerated 96-survivor inventory preserves exact normalized source diffs and records **zero untriaged** and **zero `needs_regression`** entries, with code-level equivalence proofs retained for every surviving mutation. The hosted mutation workflow enforces exact survivor-identifier and normalized-diff parity on the reviewed SHA.
- Strengthened the hosted mutation workflow to require a 95% score, internally consistent evidence, exact survivor-identifier parity, exact normalized survivor-diff/triage parity, non-empty equivalent/defensive rationales, zero untriaged records, and zero `needs_regression` classifications.
- Raised the enforced branch-coverage gate to 95% after expanding deterministic boundary and property-based regression coverage for local configuration, public review envelopes, manifests, policies, chains, traces, MCP profiles, risk lifecycle decisions, bundle diffs, CLI error handling, and unsigned statements.

- Corrected the stale adversarial-scenario claim in `docs/QUALITY.md` from ten to the source-derived count of 25.
- Extended the deterministic repository reality check to verify the source-derived adversarial scenario count, mutation record, mutation configuration, and released quality-documentation contract.
- Added exact deterministic-engine assertions for matching/default rationales, UTC timestamps, and complete bundle fields; the initial scoped mutation analysis killed 108 of 108 generated engine mutants.
- Added positive and malformed-config regression coverage for the provenance-backed LangGraph-style declaration example.
- Pinned every third-party GitHub Action used by CI and OIDC publishing to a reviewed full commit SHA, with readable release labels retained in comments.
- Extended the repository reality checker to reject mutable workflow-action references and require the factual supply-chain evidence guide.

### Security

- Added a supply-chain evidence guide that documents implemented immutable action pins, least-privilege OIDC publishing, wheel reproducibility, SBOM generation, dependency review, and intentional non-claims about signing, attestations, or external certification.

### Governance

- Added structured public issue forms for reproducible bugs and bounded feature proposals, with explicit safeguards against publishing credentials, personal data, raw trace content, tool arguments, or third-party targets.
- Added issue-template routing, a transparent ownership map, and a public contribution path while preserving private vulnerability reporting and the non-executing core boundary.

## [0.1.1] - 2026-08-13

### Release

- Promoted the TestPyPI-validated `0.1.1rc2` package to the final `0.1.1` release target.
- Added a dedicated, manually dispatched production PyPI workflow that builds and validates distributions in an unprivileged job before an isolated GitHub OIDC trusted-publishing job uploads them.
- Added an import-version synchronization regression test to keep the installed `trustweave.__version__` value aligned with the package metadata.

### Security

- The production workflow grants `id-token: write` only to its isolated publishing job, uses no stored upload token, and disables package attestations pending separately authorized signing work.
- Production publication does not change repository visibility or the local-only, non-executing product boundary.

## [0.1.1rc2] - 2026-08-13

### Fixed

- The import-visible `trustweave.__version__` now matches the version declared in `pyproject.toml`.
- A regression test prevents package metadata and import-level version values from diverging in a future release candidate.

### Validation

- This candidate supersedes `0.1.1rc1` as the TestPyPI validation target after the clean-install check identified its immutable runtime-version mismatch.

## [0.1.1rc1] - 2026-08-13

### Added

- A local CLI for scanning declared agent manifests, running synthetic policy tests, generating hash-linked evidence, rendering Markdown reports, and verifying internal evidence chains.
- `trustweave policy-check`, which creates static evidence for ordered-rule shadowing, permissive default decisions, and untrusted-input rules that allow sensitive or external actions.
- `trustweave diff`, which compares generated Agent Security Bundles and reports declared source, tool, path, matching-rule, and policy-decision changes.
- A safe baseline/candidate example that demonstrates review of a newly declared synthetic external capability without executing a tool, plus a capability-growth candidate for least-privilege review of an existing sensitive tool.
- A machine-readable policy schema and an operational quality-evidence guide.
- `trustweave trace-review`, an offline local-trace review that compares minimized tool-call metadata with declared sources, tools, flows, and deterministic policy.
- A machine-readable trace schema, clear and review-required synthetic trace fixtures, and privacy-preserving JSON/Markdown trace-review artifacts.
- Task-oriented CLI, trace-review, MCP-profile, schema-compatibility, and roadmap documentation, plus an ecosystem-research record that explains the project’s deliberate non-runtime boundary.
- `trustweave mcp-profile-check`, a static local MCP metadata profile review that validates identifier hygiene and tool-to-manifest mapping without server discovery, transport access, OAuth, token handling, or tool execution.
- A machine-readable MCP profile schema, clear and review-required profile fixtures, minimized profile-review reports, and CI gate coverage.
- Capability-level bundle diff evidence that records added and removed declared capabilities for existing tools and emits `TW-DIFF-003` when a sensitive or external tool grows its declared scope.
- A deterministic repository reality checker that validates local Markdown links, JSON schemas, workflow YAML, and documented CLI commands; hosted CI now gates on it.
- An optional `approval_control` policy declaration and `TW-POL-004` through `TW-POL-006` static review signals for missing approval documentation, incomplete action-context binding, and fail-open approval intent on sensitive/external approval-required paths.
- `trustweave policy-check --exit-on-review`, clear and deliberately review-required approval-policy fixtures, and hosted CI coverage for deterministic approval-boundary evidence.
- `trustweave sarif`, which deterministically converts selected existing policy, bundle-diff, trace, and MCP-profile review artifacts into a local SARIF 2.1.0 file with stable ordering and partial fingerprints.
- A cited ten-pattern synthetic adversarial scenario pack, additive scenario metadata, and `trustweave explain` for local policy-boundary education without prompts, payloads, model calls, or network access.
- `trustweave mcp-import`, a strict local normalizer for an already-provided MCP `tools/list` snapshot that creates a deterministic review inventory without server discovery, connection, authorization inference, or tool invocation.
- A release-blocking 90% branch-coverage gate, property-based fail-closed policy tests, Python 3.11/3.13 hosted compatibility jobs, fixed-epoch reproducible-wheel verification, and reproducible CycloneDX SBOM evidence.
- Corrected package URLs, governance review cadence, and a best-effort private security-report acknowledgement objective.
- SARIF unit coverage, CLI validation, repository-reality coverage, and hosted CI assertions for policy, diff, trace, and MCP review signals in the generated local evidence file.
- Strict manifest, policy, and scenario validation with explicit trust labels, action classes, and fail-closed behavior.
- A fully synthetic customer-support-agent example with deterministic allow, deny, and approval-required paths.
- Unit and end-to-end tests for validation, policy decisions, scenario results, evidence verification, source/tool/capability bundle diffs, static policy review, offline trace review, static MCP profile review, privacy omission, review-gate behavior, and the complete CLI workflow.
- Architecture, product-contract, threat-model, contribution, security, governance, and release documentation.
- GitHub workflows for quality checks, dependency review, Bandit static source-security scanning, package builds, isolated wheel verification, declared dependency auditing, policy review, candidate bundle-diff evidence, offline trace review, static MCP profile review, review-gate behavior, and report privacy assertions.
- An expanded 25-pattern cited synthetic adversarial scenario baseline, including MCP metadata drift, tool confusion, supply-chain provenance, delegated-agent, approval-boundary, and memory-boundary labels.
- A local MCP inventory-to-reviewer-required-manifest scaffold plus an explicit reviewer workflow that requires humans to declare sources, flows, capabilities, action classes, and policy.
- Static declaration inventories and non-executing proof walkthroughs for LangGraph, OpenAI Agents SDK, and CrewAI.
- An explicitly unsigned statement-shaped local evidence export; it preserves local digests without creating an external provenance or identity claim.
- A manual TestPyPI-only OIDC publishing workflow that separates distribution building from publishing and uses no stored upload token.

### Security

- The v0.1 core does not execute MCP configurations, agent tools, external commands from manifests, network requests, or model calls.
- The v0.1 attestation is locally hash-linked only; it is not a signed or transparency-log-backed attestation.
- The `0.1.1rc1` and `0.1.1rc2` TestPyPI workflow disables package attestations and does not publish to production PyPI, change repository visibility, or create a public release.
- Approval-control declarations are design-time evidence only; TrustWeave does not implement approval queues, authenticate approvers, or verify approval records at runtime.
- SARIF export is a local format conversion only; TrustWeave does not upload results, enable GitHub Code Security, or assert compatibility with a particular hosted code-scanning configuration.
- Scenario references and MCP tools-list metadata are local review inputs, not trusted authorization, exploit demonstrations, live-system observations, or evidence that a remote server behaves as declared.
- Fixed-epoch reproducibility is enforced for wheels only; compressed source-distribution reproducibility is not yet a release gate.

### Known limitations

- No MCP proxy, runtime enforcement, framework SDK, automatic discovery, external signature provider, or enterprise integration is included.
- JSON inputs work with no dependency. Safe YAML parsing requires the optional PyYAML dependency.
- Production publication uses the dedicated trusted-publishing workflow; external signing, hosted-result uploads, and runtime integrations remain separately authorized work.
