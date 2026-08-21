# TrustWeave Evaluation Conflicts and Limitations

## Author and maintainer role disclosure

TrustWeave maintainers and contributors may design the synthetic corpus, write the evaluation documents, administer the reviewer protocol, triage feedback, and author technical-report material. Their development observations are valuable release and engineering evidence, but they are **not independent-review evidence** for the revision they authored.

Any paper, blog post, release note, archive record, or presentation that uses evaluation material must disclose: the authorship relationship to TrustWeave; the source revision and evidence cutoff; reviewer recruitment channel; participant categories; any prior academic, professional, or financial relationship with reviewers; and any role in coding or interpreting responses.

## Independence criteria

A response may be counted as independent only if the reviewer did not author or materially direct the evaluated TrustWeave or corpus revision. A reviewer’s name need not be published, but their independence category and any relevant relationship must be recorded in the private study ledger. If independence is uncertain, the response must be reported as non-independent or excluded from the independent-results summary.

## Methodological limitations

| Limitation | Consequence for interpretation |
|---|---|
| Synthetic fixtures | Corpus success shows conformance on supplied declarations, not behavior of a live system. |
| Small, self-selected reviewer group | Results are exploratory and not population-wide adoption or usability evidence. |
| Author-designed tasks | Expected categories may reflect the authors’ framing; counterexamples and external review are essential. |
| Self-reported decision support | A reviewer statement does not establish causal reduction of risk, incidents, or review time. |
| Local/offline workflow | Results do not establish runtime enforcement, remote integration safety, availability, or service scalability. |
| Input authenticity not established | TrustWeave reviews supplied files and metadata; it does not prove that they are complete, truthful, or current. |
| Version-specific observations | Findings apply only to the named tag/commit, corpus, environment, and protocol cutoff. |

## Prohibited interpretations

No evaluation result may be described as proof that TrustWeave is secure, that an AI agent is secure, that a policy is enforced at runtime, that an attack was prevented, that an MCP server was verified, that reviewers represent all developers, or that the project has achieved broad adoption. The tool remains an aid to human review of supplied local declarations and pre-recorded metadata.

## Handling disagreement and negative results

Maintainers must preserve material negative feedback, corpus mismatches, failed setup attempts, and reviewer disagreements. Each must be triaged as fixed, accepted limitation, disputed with rationale, deferred, or withdrawn. A project improvement may be released in response to feedback, but the original feedback must not be rewritten as if the later version had been evaluated.

## Current status

The documents and corpus framework are prepared by TrustWeave contributors. Independent reviewers, pilot participants, outcome data, comparative benchmarks, and external adoption evidence are **not yet collected**.
