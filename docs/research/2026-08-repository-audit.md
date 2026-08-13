# TrustWeave Repository and Documentation Audit — August 2026

## Audit scope

The review considered the repository’s current product workflow, command-line discoverability, documentation quality, test coverage, governance, hosted checks, and consistency with high-quality agent-security projects.

## Current assessment

| Dimension | Current rating | Evidence | Gap to close |
|---|---:|---|---|
| Core product clarity | 8.8/10 | The README explains scan, test, attest, report, verify, policy-check, and diff. | The tool has no observed-evidence workflow; it explains declared state more strongly than recorded behavior. |
| Developer experience | 8.0/10 | Basic quick start and candidate-bundle diff exist. | The repository lacks a CLI reference, sample output walkthrough, trace-review guide, and a correct clone target for the actual repository. |
| Documentation accuracy | 7.8/10 | Architecture, product contract, quality guide, threat model, release procedure, and security policy exist. | Several documents retain v0.1-only wording, omit the latest checks, and do not fully connect command contracts to artifacts. |
| Engineering and tests | 9.0/10 | Typed Python, 12 deterministic tests, package build, isolated wheel check, linting, type check, static source scan, and dependency audit exist. | A larger integration scenario should connect a declaration, a recorded trace, a policy result, and an evidence report. |
| Governance | 9.0/10 | Private repository, protected `main`, required status check, dependency review, release process, code of conduct, and security policy exist. | Maintainer ownership and release/versioning guidance need more explicit operating details. |
| Evidence model | 8.7/10 | Bundle, scenario result, report, local hash-chain attestation, policy review, and diff artifacts exist. | The local evidence model does not yet consume observed trace records or distinguish a behavior-review artifact from a declared-policy review. |
| Overall | **8.6/10** | A solid, safe pre-release foundation. | A focused offline trace-review feature plus a documentation rework can credibly move the repository above 9.5/10. |

## Documentation defects found

| Finding | Impact | Required correction |
|---|---|---|
| README clone command references `AbdulrahmanRezki/trustweave`, while the active repository is `MohammadThabetHassan/trustweave`. | New contributors cannot reliably follow the first command. | Use the actual repository URL and explain private-repository access. |
| README commands are grouped but do not explain artifact contracts, input contracts, exit codes, or expected review states. | Users cannot confidently integrate the CLI into CI. | Add a concise CLI reference and task-oriented guides. |
| CONTRIBUTING omits the current static security scan, build, dependency audit, policy review, and diff workflow. | Contributor checks are inconsistent with CI. | Derive the contributor checklist from `docs/QUALITY.md`. |
| SECURITY says the project does not provide vulnerability scanning, but CI now runs a static source-security scan. | Scope language is stale and ambiguous. | State precisely that the project does not scan external agent deployments, while repository source is statically scanned. |
| Documentation does not distinguish declared architecture evidence from observed trace evidence. | The project’s evidence model has no clear extension path. | Add a trace-review guide with strict privacy and non-execution boundaries. |
| No structured project roadmap or schema compatibility policy exists. | Potential contributors cannot judge stability or select an extension. | Add a roadmap and schema/versioning guide. |

## Selected next feature: offline trace-policy review

The feature will read a local JSON trace, a TrustWeave manifest, and a TrustWeave policy. It will not connect to a target, execute a tool, load an adapter, call a model, access credentials, or inspect raw message text.

### Acceptance criteria

1. Strictly validate a trace with `messages`, `tool_calls`, and `events` lists.
2. Require each observed tool call to name a declared source and a tool using one accepted name field: `name`, `tool`, or `tool_name`.
3. Compare each call to the manifest and deterministic policy, reporting unknown tools, undeclared source-to-tool paths, policy-denied calls, and approval-required calls.
4. Report untrusted-context events only as structured counts and types; never reproduce message content or tool arguments in reports.
5. Produce stable JSON and Markdown artifacts and support an `--exit-on-review` CI mode.
6. Include safe and review-required synthetic trace fixtures, deterministic unit tests, an end-to-end CLI test, schema documentation, and a task-oriented guide.

## Selected documentation and operations work

1. Replace the README with a task-oriented entry point, corrected private-clone instructions, artifact map, concise command table, and links to dedicated guides.
2. Add `docs/CLI_REFERENCE.md`, `docs/TRACE_REVIEW.md`, `docs/SCHEMA_AND_COMPATIBILITY.md`, and `docs/ROADMAP.md`.
3. Update CONTRIBUTING, SECURITY, QUALITY, and the changelog to match actual tools and safety boundaries.
4. Extend CI to run the offline trace-review fixtures and fail in explicit review-gate mode where expected.
