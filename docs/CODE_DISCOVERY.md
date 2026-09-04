# Local code discovery

`trustweave discover` reads local Python source and reports the tool surface it can see:
what an agent can call, what each call appears to do, and where that disagrees with the
manifest you declared.

It parses. It does not import, compile, install, execute, or resolve the dependencies of
the code it reads, and it does not fetch anything remote. See
[ADR-0006](adr/ADR-0006-LOCAL-STATIC-SOURCE-ANALYSIS.md) for why this narrows a previously
published boundary and how the boundary was restated.

```bash
trustweave discover \
  --source path/to/agent \
  --manifest agent.manifest.json \
  --output-dir artifacts
```

Without `--manifest` you get the discovered surface and a draft. With it you also get
drift in both directions and a declaration-coverage figure.

## What it will not do

**It will not infer trust.** Every source in the emitted draft carries the literal
`unknown`. No input can make it emit anything else. Deciding that a source is trusted is
the security judgement the whole model rests on; a tool that guessed it would put a guess
behind an attestation.

**It will not guess an action class.** Ambiguity produces `unknown` with a reason:

| Reason | What it means |
|---|---|
| `UNRESOLVED_CALLEE` | The call target could not be tied back to an imported symbol. |
| `DYNAMIC_DISPATCH` | Behaviour is selected at runtime, through a lookup table, `getattr`, or `eval`. |
| `NONLITERAL_ARGUMENT` | An argument that decides the effect is a variable, so both readings stay open. |
| `BODY_UNAVAILABLE` | The tool was declared somewhere the implementation could not be located. |
| `BUDGET_EXHAUSTED` | An analysis limit was reached before the reachable set was covered. |
| `LEXICAL_ONLY` | Only naming evidence matched, with no observed behaviour. |

**It will not treat a name as behaviour.** A tool called `ssn_lookup` that only formats a
string is not sensitive. Naming may push a tool to `unknown`; it never assigns a class.

**It will not match a bare attribute.** `.post`, `.execute` and `.write` mean nothing
without knowing the receiver, so a symbol counts only once it resolves through an import
binding or a tracked constructor.

## How an action class is proposed

Signals are gathered over the tool body and module-local helpers it calls, to a bounded
depth, with each hop recorded. Precedence is `sensitive` > `external` > `write` > `read`.

| Class | Recognised by |
|---|---|
| `external` | HTTP and mail clients, sockets, cloud and model SDK clients, and shelling out to a transfer tool such as `curl` or `scp`. |
| `write` | `open` in a writing mode, `pathlib` mutations, `os` and `shutil` filesystem changes, and literal SQL whose leading keyword writes. |
| `sensitive` | Process launch and arbitrary-code execution, secret-shaped environment reads, credential paths and key material, and unpickling. |
| `read` | Everything recognised that only reads. |

`read` is a positive classification, not a fallback. A tool with no recognised effect at
all is `read`; a tool whose effects could not be resolved is `unknown`. Collapsing those
two would teach reviewers to bulk-accept `unknown`.

## Declaration coverage

Coverage is the share of discovered tools that the manifest declares, matched on exact
name, reported in integer basis points and rendered to two decimal places. Without a
manifest, or with nothing discovered, the fields are omitted rather than reported as a
misleading 100%.

Coverage measures name agreement. It does not establish that the code is complete, that
the manifest is complete, or that either is correct.

Manifest tool names must match `^[a-z][a-z0-9_-]{0,63}$`, and Python function names need
not. A tool renamed to satisfy that grammar appears in both drift directions;
`probable_renames` pairs the likely match for a reader without moving either entry or
affecting coverage.

## The draft is not a manifest

`manifest_draft` deliberately fails validation. `unknown` and `REVIEW_REQUIRED` are
outside the accepted vocabularies, so `parse_manifest` rejects it until a reviewer
resolves every placeholder. A draft that validated would eventually be passed to `scan`
as though it had been reviewed, which is the specific failure this design refuses.

## Findings

All ten `TW-CODE-*` rules are `review` severity. A static inference is a review
obligation, never a blocking verdict, and discover findings are not registered for
`risk-check --fail-on`.

The two that most often matter:

- **`TW-CODE-002`** — the manifest declares one action class and the code proposes
  another. This is the mislabelled trust boundary the product previously had no way to see.
- **`TW-CODE-003`** — a tool exists in code and is not declared at all.

## How a tool is recognised

A tool is whatever the agent can be asked to invoke, and frameworks say so in several ways.
Each recognised form is listed here because the set is the boundary of what discovery can
see: a form that is missing is not reported as a gap, it is simply absent from the draft.

| Form | Example | Name taken from |
|---|---|---|
| Decorator | `@tool` on a function | the decorator's `name=`, else the function |
| Plugin method | `@kernel_function(name="probe")` on a method | the decorator's `name=` |
| Server decorator | `@server.tool()`, `@server.call_tool()` | the decorator's `name=`, else the function |
| Factory | `StructuredTool.from_function(func=..., name=...)` | the `name=` argument |
| Class-based tool | a `BaseTool` subclass with `_run` or `_arun` | the `name` class attribute, else the class |
| Bound list | a function passed in `tools=[...]` to an agent constructor | the function |

Two names can differ. A factory registers `object_summary` while the code that runs is
`summarize_bucket_object`, and a class-based tool registers `fetch_page` while the body sits
in `FetchTool._run`. The artifact records the registered name as `name` and the implementing
symbol as `implementation` whenever they differ, and the rendered report prints both -- the
first is what the model sees, the second is what a reviewer has to open.

## Why a tool is left unknown

A refusal is a result, not a gap. Each reason names the specific thing that could not be
established, so a reviewer knows what to check rather than being told to check everything.

| Reason | What it means |
|---|---|
| `UNRESOLVED_CALLEE` | the call reaches a name this module does not define or import |
| `DYNAMIC_DISPATCH` | the callee is chosen at runtime, from a subscript or an unresolved call |
| `NONLITERAL_ARGUMENT` | the argument decides the class and is not a literal here |
| `BODY_UNAVAILABLE` | the registered target names no body the analyzer can read |
| `LEXICAL_ONLY` | a name suggests personal data but nothing in the body acts on it |
| `BUDGET_EXHAUSTED` | the reachable set grew past the per-tool bound |

One refusal does not always withhold an answer. An effect at the top of the precedence order
-- a credential read, an arbitrary process launch -- cannot be outranked by anything an
unresolved call might also do, so it is reported even when something else in the same tool
could not be placed. Below that top class the refusal stands, because an unseen effect
really could be worse than what was observed.

## Limits

Discovery is bounded by design. A public function that is not decorated as a tool, and not
bound into a `tools=[...]` list reaching an agent constructor, is not reported as a tool —
enumerating every function would inflate a draft with things that are not tools. Frameworks
outside the set listed above are not discovered, and a tool whose name is built at runtime --
returned as a `Tool(name=...)` literal from a handler, say -- is discovered under the handler
rather than under the name the model is given. AST shapes vary between interpreter
versions, so a run on a different interpreter may resolve a different symbol set.

Every artifact records these limits inline, so a reader who never opens this page still
sees what the result does not establish.
