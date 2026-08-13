# Local CI Integration Assets

TrustWeave includes repository-local starting points for deterministic evidence generation. None publishes a release, uploads SARIF, posts a pull-request comment, uses credentials, enables a repository service, or executes a declared agent, tool, model, MCP server, or live endpoint.

| Asset | Purpose | Explicit owner action required before broader use |
|---|---|---|
| `.github/actions/trustweave` | Composite action for scan, synthetic test, and policy review. A caller must check out the repository and provide Python. | Add any artifact upload, SARIF ingestion, or protected-branch policy separately. |
| `.pre-commit-config.yaml` | Local Ruff and mypy checks using the contributor’s existing environment. | Install `pre-commit` locally and opt in with `pre-commit install`. |
| `examples/ci/gitlab-ci.yml` | GitLab job that retains artifacts under the job’s artifact mechanism. | Review retention and access policy for the target project. |
| `examples/ci/Jenkinsfile` | Jenkins pipeline that archives generated local artifacts. | Review agent, image, retention, and artifact-access configuration. |

A secure GitHub caller can invoke the composite action using read-only permissions and a pinned checkout action:

```yaml
permissions:
  contents: read
jobs:
  trustweave:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5
      - uses: ./.github/actions/trustweave
        with:
          manifest: examples/support-agent.manifest.json
          policy: policies/default-policy.json
          scenarios: scenarios/default-scenarios.json
```

The action intentionally leaves artifact publishing and SARIF upload out of its default behavior. Those operations can disclose local evidence to a host and require a separate owner decision.
