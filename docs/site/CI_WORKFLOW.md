# Local CI workflow

TrustWeave’s CI assets generate and validate **local evidence only**. They do not upload SARIF, post pull-request comments, access credentials, connect to MCP servers, execute declared tools, or inspect a live deployment.

## Repository-local composite action

The checked-in action at `.github/actions/trustweave` installs the checked-out package, performs a manifest scan, executes synthetic scenarios, and reviews policy structure. It exposes the three local paths it writes: `bundle`, `test-results`, and `policy-review`.

```yaml
permissions:
  contents: read
jobs:
  evidence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - id: local-evidence
        uses: ./.github/actions/trustweave
        with:
          manifest: examples/support-agent.manifest.json
          policy: policies/default-policy.json
          scenarios: scenarios/default-scenarios.json
          output-dir: action artifacts
      - shell: bash
        run: test -s "${{ steps.local-evidence.outputs.bundle }}"
```

Set `fail-on-review: "true"` only when the caller deliberately wants policy review findings to fail the workflow. This option is a review gate, not runtime enforcement.

## Local pre-commit validation

The repository’s `.pre-commit-config.yaml` keeps maintainer Ruff and mypy checks separate from declaration validation. It validates staged local configuration, manifests, policies, scenario packs, and chain manifests through the same typed parsers used by the product.

```shell
pre-commit install
pre-commit run --all-files
```

The hooks use the contributor’s local Python environment and do not contact external services.

## Code scanning and container

The CodeQL workflow analyzes Python and GitHub Actions code through pinned action revisions. Dependabot tracks supported dependency and action updates; source workflows reject mutable third-party action references.

The `Dockerfile` builds a minimal image from an immutable official Python digest, installs TrustWeave with no dependency resolution, and runs as the unprivileged `trustweave` user. The image’s health check invokes `trustweave --help`; normal commands remain local and read-only-compatible.

```shell
docker build --tag trustweave:0.2.0 .
docker run --rm --read-only trustweave:0.2.0 --help
```

Docker is required to execute these container commands. The image does not add a daemon, background job, network listener, credential integration, or automatic evidence publication.
