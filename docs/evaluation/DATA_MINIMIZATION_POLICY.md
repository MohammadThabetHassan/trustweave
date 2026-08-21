# TrustWeave Evaluation Data-Minimization Policy

## Purpose

This policy limits future TrustWeave evaluation to the minimum information needed to assess the reproducibility and clarity of deterministic local evidence artifacts. It applies to the synthetic corpus, reviewer study, pilot materials, feedback records, paper appendix, and archive package.

The default approved input is a checked-in synthetic fixture. Any departure requires a documented human-author decision before collection or processing.

## Approved material

The following material may be used when it is synthetic, non-sensitive, and consistent with the product contract.

| Material | Conditions |
|---|---|
| Agent manifests | Synthetic sources, tools, flows, data classes, trust labels, and action classes only. |
| Policies and scenarios | Fixed harmless declarations and assertions; no exploit payload, active probe, or target-specific behavior. |
| Trace-review fixtures | Minimized source/tool/event metadata only; no message content, tool arguments, identifiers, or timestamps that can identify a person or production system. |
| MCP metadata profiles | Synthetic transport/resource identifiers and mapping data only; no host reachable from the evaluator, token-like URI component, credential, or live discovery behavior. |
| Reviewer feedback | Fixed-choice responses and optional comments after redaction and consent. |
| Environment evidence | Tool version, operating-system family, Python version, and non-sensitive error summary only when needed to diagnose reproducibility. |

## Prohibited material

The following material must not be added to the repository, corpus, public issue tracker, paper archive, or reviewer task pack.

1. Credentials, API keys, tokens, passwords, cookies, private keys, certificates, session identifiers, or token-like URI components.
2. Personal data, contact details, user identifiers, customer records, employee data, or identifiable production logs.
3. Proprietary source code, private repositories, internal architecture diagrams, unreleased vulnerabilities, or confidential policies.
4. Message content, tool arguments, full prompt/response traces, files from live agents, or evidence that establishes a person’s behavior.
5. Live hostnames, routable targets, production MCP servers, service-discovery requests, OAuth flows, remote scans, exploit payloads, or instructions that make an external request.
6. Downloads, binaries, plugins, browser scripts, telemetry collectors, or evaluation tooling that requires a network connection.
7. Fabricated reviewer identities, reviews, user counts, benchmark measurements, pilot outcomes, or adoption claims.

## Redaction and review procedure

A contributor proposing a non-synthetic pilot artifact must first create a private, human-reviewed redaction checklist. The checklist must confirm that the artifact contains no prohibited material and that its source organization or owner has authorized the limited use. The public corpus receives only a reconstructed synthetic equivalent unless a separate written decision approves another handling path.

Before a response or pilot artifact is published, two human reviewers must confirm that it is safe to disclose, that contextual details cannot reasonably re-identify a participant or organization, and that the associated claim is limited to the supplied evidence class. When in doubt, omit the material and report the limitation.

## Storage and retention

The checked-in corpus must contain only approved synthetic data. Consented reviewer feedback should be retained only for the duration stated in the protocol and in an access-controlled location separate from the repository. Public archives should contain only anonymized, consented, and reviewed aggregate data or excerpts. A withdrawal request received before the evidence cutoff must be honored where technically and legally possible.

## Incident handling

If prohibited material is committed, attached to an issue, or included in a draft archive, maintainers must stop distribution, restrict access where possible, follow the project security-reporting route, remove the material through the appropriate repository and hosting procedure, and document only the minimum non-sensitive remediation record. A public issue must never expose a secret or the sensitive material itself.

## Current status

The current evaluation corpus framework is synthetic-only. No reviewer data, pilot data, production artifacts, or identifying data are collected by this policy.
