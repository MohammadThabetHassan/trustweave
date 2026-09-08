# Running the Feynman research agent against this work

[`advaitpaliwal/feynman`](https://github.com/advaitpaliwal/feynman) (MIT) is an AI research
agent. It earned its place here on the first run by surfacing a 2021 SACMAT paper on
mutation analysis of access-control policies that a manual related-work search had missed.
This records the configuration, because getting it to run entirely on a local model took
four wrong turns and none of them are in the tool's documentation.

## Why local, and not a hosted provider

The manuscript is deliberately kept out of the public repository, because a journal and its
similarity check read a publicly posted full text as prior dissemination. Sending that same
text to a hosted model is the same exposure in a different form, and some providers retain
or train on what they are sent. So the agent runs against a local Ollama model and the
manuscript never leaves the machine.

The literature commands are a separate case and are safe against any backend: `feynman
paper` and `feynman rank` send a DOI or a topic string to OpenAlex and arXiv, not the paper.

## Install

```
npm install -g @advaitpaliwal/feynman     # not the curl|bash one-liner: this is inspectable
```

It lands in the user npm prefix, so no root is needed. It runs on Node 22 despite the
repository's `.nvmrc` asking for 24.

## Turn telemetry off first

Telemetry defaults to **on**, shipping to a PostHog project:

```
# ~/.feynman/.env
FEYNMAN_TELEMETRY=off
PI_OTEL_CAPTURE_CONTENT=metadata_only
```

## Point it at a local model

Three things that do not work, recorded so nobody repeats them:

1. **`OPENAI_BASE_URL` is ignored for requests.** Setting it plus `OPENAI_API_KEY` makes
   `feynman model list` show an authenticated `openai` provider with 32 models, and
   `feynman status` report `Model valid: yes` --- and then the request goes to
   **api.openai.com** and fails with a 401 on the fake key. The configuration looks correct
   and is not.
2. **`feynman model set` rejects any id outside its catalog**, so a local model cannot be
   named directly this way.
3. **Aliasing the local model to a catalog name** (`ollama cp qwen38-oc gpt-4.1`) satisfies
   the validator and still sends the request to OpenAI, because of (1).

What works is registering a custom provider. The interactive `feynman setup` writes it; the
same file can be written directly, which is what a scripted setup needs:

```jsonc
// ~/.feynman/agent/models.json
{
  "providers": {
    "ollama": {
      "baseUrl": "http://localhost:11434/v1",
      "apiKey": "local",              // a placeholder; Pi requires the field
      "api": "openai-completions",
      "models": [{ "id": "qwen38-oc:latest" }]
    }
  }
}
```

Then:

```
feynman model set ollama/qwen38-oc:latest
feynman --prompt="Reply with exactly: local round trip ok"     # verify before trusting it
```

**Verify the round trip before sending anything confidential.** That check is the only thing
that distinguishes a working local setup from the convincing-looking broken one in (1).

## Context length

The manuscript is around 15{,}500 tokens. Ollama's default context is far smaller, and it
truncates silently rather than erroring, so a critique of a paper it only half read would
look perfectly plausible. Confirm the model has room:

```
ollama show --modelfile qwen38-oc | grep num_ctx      # 131072 here
```

## Keep its output out of the repository

The agent writes reports into `outputs/` in the working directory and state into
`.feynman/`. Both are gitignored. `scripts/reality_check.py` skips them too, which it had
to learn: its Markdown scan read `<https://doi.org/...>` --- the bracketed form the agent
writes for every DOI, and valid Markdown --- as a broken local path, and reported nineteen
of them.

## What it is good for here

- `feynman rank "<topic>"` --- prior-art sweep. Noisy: most of the top twenty-five hits for
  this paper's topic were medical guidelines, because "testing" is a loaded word. Two were
  real and both were uncited. Worth running for that alone.
- `feynman paper <doi>` --- resolves access routes, and independently confirmed a citation.
- `feynman --prompt=...` --- adversarial review against the local model.

Every reference it surfaces is still checked against Crossref before it is cited, the same
as every other reference in the bibliography. The agent finds candidates; it does not
verify them.
