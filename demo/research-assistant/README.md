# Research-assistant demo

A worked TrustWeave review of a realistic agent, ending with the tool catching a security-relevant config change that looks innocent.

## The setup

A research assistant that answers questions by reading web pages and internal notes, queries company metrics on request, and posts summaries to Slack. Six declared flows connect three input sources to four tools:

- `user_request` (trusted) — what the authenticated user types
- `web_page_content` (untrusted) — fetched web text, prompt-injection territory
- `metrics_query_result` (conditional) — confidential rows from the internal database

## Run it

```shell
pip install trustweave
./run.sh
```

About two seconds. Nothing executes, nothing leaves your machine. Two files matter at the end:

- `artifacts/report.md` — the review of the current setup
- `artifacts/diff/bundle-diff.md` — what a proposed change would do

## What part 1 shows: the review

Six declared flows get a decision each:

| Source | Tool | Decision |
|---|---|---|
| user_request | fetch_web_page | allow |
| user_request | summarize_notes | allow |
| user_request | query_metrics_database | **deny** |
| metrics_query_result | post_to_slack | require_approval |
| web_page_content | query_metrics_database | **deny** |
| web_page_content | post_to_slack | **deny** |

Two things worth noticing:

1. **`user_request → query_metrics_database` is denied by default.** The policy allows trusted sources to use read-only tools and denies untrusted ones from sensitive tools, but nobody wrote a rule for *trusted → sensitive*. It fails closed. Every individual rule looked reasonable; the matrix still had a hole. This is exactly the kind of gap that survives normal code review.
2. **Web content is walled off from both sensitive and external tools.** If someone later declares a flow where a fetched page triggers a database query — a classic prompt-injection path — the scan flags it immediately.

## What part 2 shows: catching a quiet weakening

A week later someone proposes this one-rule change "to save time":

> RA-002: confidential results reach Slack only with human approval → **allow** ("the weekly summary is routine")

Sounds harmless. `run.sh` scans the candidate policy and diffs it against the reviewed baseline:

```
$ trustweave diff \
    --base artifacts/agent-security-bundle.json \
    --head artifacts/candidate/agent-security-bundle.json \
    --output-dir artifacts/diff
Wrote bundle diff: artifacts/diff/bundle-diff.json and artifacts/diff/bundle-diff.md
```

The diff report flags it in two places:

| Source | Tool | Before | After |
|---|---|---|---|
| metrics_query_result | post_to_slack | require_approval | **allow** |

```
Review signals
severity  identifier     message
review    TW-DIFF-008    One or more declared policy rules became less
                         restrictive; review the changed decision boundaries...
```

No application code changed. No test failed. But confidential data leaving the company now needs no sign-off, and that's visible before merge instead of after.

## Try it yourself

Open `policies/boundary-policy.json` next to `policies/candidate-relaxed.json` — the only difference is RA-002. Change something else: add a flow from `web_page_content` to `post_to_slack`, re-run, and see it denied by RA-004. Then delete RA-004 and run step 2 again (`trustweave test`) — the regression scenario fails. That's the loop: declarations describe, policies decide, scenarios lock decisions in place.

## Files

| File | Role |
|---|---|
| `manifests/research-agent.manifest.json` | What the agent declares: sources, trust levels, tools, flows |
| `policies/boundary-policy.json` | The reviewed rules producing the decisions above |
| `policies/candidate-relaxed.json` | The "harmless" proposal that part 2 catches |
| `scenarios/regressions.json` | Synthetic cases the policy must keep passing |

TrustWeave can also import declarations from LangGraph / OpenAI Agents / CrewAI setups and saved MCP `tools/list` snapshots — see the [integration routes](../../docs/site/INTEGRATIONS.md).

One boundary to keep straight: this is evidence about *declarations*, not proof about runtime behavior. The report says so itself.
