# Case studies

Real usage stories help the next team decide whether TrustWeave is worth their time. If you've used it on an actual agent — even a small internal one — consider writing it up using the template below.

How to submit: open a pull request adding `docs/case-studies/<your-handle>-<date>.md`, or describe your experience in a [GitHub issue](https://github.com/MohammadThabetHassan/trustweave/issues/new/choose) if you'd rather not publish details. Don't include real customer data, private server names, credentials, or proprietary manifests — sanitize first, then share.

A few ground rules so entries stay honest:

- Say what you actually ran and what you actually found.
- It's fine to write "we didn't find anything new" — that's still useful signal.
- No deployment-security conclusions: TrustWeave reviews declarations, and case studies should respect that boundary.

## Template

```markdown
# Case study: <one-line description of the agent>

**Date:** YYYY-MM-DD
**Environment:** <e.g., LangGraph agent, 4 tools, internal support bot>
**TrustWeave version:** <x.y.z>

## What we reviewed

<Which manifest/policy/snapshot, how many declared flows, where the
declaration came from (hand-written, framework export, MCP inventory).>

## What we changed because of it

<New rules added, flows removed, approval controls made explicit,
scenarios added to CI. "Nothing — the review confirmed our config" is
a valid entry.>

## What it didn't cover

<Honest limits you hit: runtime behavior, undeclared tools, anything
outside the declaration.>

## Would we run it again?

<Plain answer.>
```

## Entries

None yet — yours could be the first.
