# How TrustWeave compares

TrustWeave occupies one specific niche: **static review of declared agent configurations**. If you're evaluating security tooling for an agent stack, you probably want more than one tool. Here's how the approaches fit together.

| Approach | Question it answers | When it runs | Examples |
| --- | --- | --- | --- |
| Declaration review (TrustWeave) | "Is this agent's *declared* configuration sound, and did it just change?" | Before deploy, in code review | TrustWeave |
| MCP/server scanners | "Are the MCP servers and tools I'm connecting to known-bad?" | Install time, ad hoc | e.g. `mcp-scan` and similar tools |
| Runtime guardrails | "Is *this particular request* safe to let through?" | Every call, in production | Policy engines, input/output filters |
| Prompt-injection evals | "How does the model behave under attack?" | Benchmarks, red-team cycles | Eval suites, adversarial testing |
| SAST/secrets scanning | "Does the *code* have vulnerabilities or leaked keys?" | CI | Bandit, CodeQL, gitleaks |

These don't compete. A reasonable stack uses several: SAST on the code, a scanner on third-party MCP servers, TrustWeave in the pull request that changes the agent's configuration, and runtime controls for what static review can't see.

## What TrustWeave does that the others don't

Configuration drift is invisible to everything above except declaration review. A pull request that adds a flow from an untrusted source to an external tool changes your attack surface without touching application code. SAST sees no vulnerability, runtime guards meet the new path only after deployment, and scanners only cover the servers involved. TrustWeave makes that diff explicit and reviewable, deterministically, from checked-in files.

## What we won't claim

- TrustWeave doesn't detect real prompt injection, evaluate model behavior, or validate that tools do what their names suggest.
- A passing scan means the declaration is consistent and policy-covered — not that the deployed agent is secure.
- We can't verify runtime enforcement of `require_approval` decisions; those need the production control they name.

If another project already covers this niche better for your stack, use it — and tell us what it does well.
