# TrustWeave Evaluation Charter

## Purpose

This charter governs future evaluation of TrustWeave as a **local-first, non-executing security-evidence tool**. It establishes how maintainers may collect, analyze, and publish evidence about the clarity and reproducibility of TrustWeave review artifacts without overstating what the tool measures.

The charter applies to the versioned synthetic evaluation corpus, independent reviewer protocol, and any consented pilot built from safe, sanitized inputs. It does not authorize collection of production data, credentials, personal data, proprietary source code, live-target observations, or runtime agent activity.

## Evaluation questions

The evaluation asks only the following questions.

| ID | Question | Permitted evidence | Excluded conclusion |
|---|---|---|---|
| EQ-1 | Can an independent reviewer reproduce the supplied local corpus workflow? | Offline setup outcome, deterministic command result, and documented blocker. | General usability or production deployability. |
| EQ-2 | Can a reviewer distinguish the declared evidence, review signal, and stated limit in a TrustWeave report? | Structured reviewer response to a supplied synthetic case. | Runtime-security effectiveness or attack prevention. |
| EQ-3 | Does a supplied artifact help a reviewer describe whether a declared change needs further human review? | Self-reported decision-support response for a synthetic or consented sanitized task. | Automatic authorization, enforcement, or causal reduction of incidents. |
| EQ-4 | Which clarity, setup, or evidence-boundary problems do reviewers identify? | Consent-based structured and narrative feedback. | Population-wide adoption or productivity gains. |

## Evidence classes

Every public statement arising from this evaluation must be labeled with one of the following evidence classes.

| Class | Meaning | Publication rule |
|---|---|---|
| **Release evidence** | Facts verified for a versioned TrustWeave release. | Link to the tag, release record, and exact supporting artifact. |
| **Corpus evidence** | Deterministic result from a synthetic, versioned corpus case. | Name the corpus version, case ID, command, and expected assertion. |
| **Independent review evidence** | Feedback from a person with no authorship role in the evaluated TrustWeave revision. | Record consent, reviewer category, protocol version, and anonymization method. |
| **Pilot evidence** | A consented, sanitized task that follows the approved protocol. | State its narrow context, data minimization, and non-generalizability. |
| **Planned evidence** | A method, template, or artifact prepared before collection. | Mark it **not yet collected**; never report it as an outcome. |

## Eligibility and independence

An independent reviewer must not be an author of the TrustWeave revision or corpus revision being evaluated. A reviewer may be a practitioner, researcher, educator, open-source maintainer, or developer familiar with software review. Existing professional or academic relationships with authors must be disclosed in the study record and paper.

Core contributors may test the corpus and administer the protocol, but their observations are release or internal-development evidence, not independent-review evidence.

## Data minimization and participant protection

The evaluation may use only the checked-in synthetic corpus or a separately approved, sanitized pilot pack. Reviewers must not provide credentials, personal data, production traces, proprietary manifests, customer information, copied source repositories, live targets, exploit payloads, or tool arguments/message contents. Any optional identifying contact information used to schedule a review must be kept outside the corpus and excluded from public research artifacts.

Before collecting identifiable feedback or publishing raw responses, the maintainers must determine whether their institution, instructor, employer, or jurisdiction requires additional review or approval. This charter does not replace those obligations.

## Method and analysis rules

The reviewer protocol fixes the task pack, commands, questions, and analysis fields before recruitment. Maintainers must report completed and failed setup attempts, positive and negative feedback, unresolved disagreements, and withdrawn responses using the criteria set before analysis. The final report must state sample size, recruitment channel, participant categories, conflicts, missing data, and all material deviations from the protocol.

The evaluation is exploratory unless a future pre-registered design and sufficient independent sample justify a stronger statement. Descriptive statistics and anonymized qualitative themes may be reported; causal, population-wide, efficacy, or performance claims must not be inferred from a small reviewer sample.

## Explicit non-claims

TrustWeave evaluation under this charter does **not** establish that TrustWeave:

1. enforces runtime security or authorizes deployments;
2. prevents attacks, vulnerabilities, incidents, or prompt injection;
3. observes live MCP servers, agent executions, tool calls, user data, or input authenticity;
4. improves productivity, adoption, compliance, or incident rates in general;
5. validates arbitrary repositories, production systems, or third-party integrations; or
6. provides provenance beyond the exact package or artifact evidence specifically documented for a release.

## Evidence cutoff and publication approval

A public evaluation record must name its TrustWeave tag or commit, corpus version, protocol version, collection dates, and evidence cutoff. Before public posting, paper submission, or archive deposit, a human author must review claims against the claim–evidence–limitation matrix and confirm that every result is traceable to a permitted evidence class.

## Current status

The charter and corpus framework are **prepared**. Independent reviewer feedback, pilot results, DOI archival, comparative benchmarks, and external adoption evidence are **not yet collected**.
