# Installation and five-minute local review

TrustWeave supports **Python 3.11 and later**. Every command reads local files and writes local artifacts — nothing runs, nothing phones home.

## Install the published package

```shell
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip trustweave
trustweave --help
# Equivalent module invocation:
python -m trustweave --help
```

Safe YAML parsing is optional. Install it only when your supplied declarations use YAML:

```shell
python -m pip install 'trustweave[yaml]'
```

## Review the included example

The source tree contains a self-contained example. The following workflow reads only checked-in files and produces local artifacts under `artifacts/`.

```shell
git clone https://github.com/MohammadThabetHassan/trustweave.git
cd trustweave
python -m pip install -e .
rm -rf artifacts

trustweave scan \
  --manifest examples/support-agent.manifest.json \
  --policy policies/default-policy.json \
  --output-dir artifacts
trustweave test \
  --policy policies/default-policy.json \
  --scenarios scenarios/default-scenarios.json \
  --output-dir artifacts
trustweave report --output-dir artifacts
```

| Artifact | Review purpose |
| --- | --- |
| `artifacts/agent-security-bundle.json` | Deterministic policy decisions for declared flows |
| `artifacts/security-test-results.json` | Results for fixed synthetic policy scenarios |
| `artifacts/report.md` | Human-readable summary of findings and limitations |

Run `trustweave attest --source-revision local --output-dir artifacts` only after reviewing the source revision you want to identify. Then verify the exact local files under review with `trustweave verify --attestation artifacts/attestation.json --bundle artifacts/agent-security-bundle.json --test-results artifacts/security-test-results.json`. Omitting the bundle and test-result paths checks only the statement’s internal consistency, not a reviewer’s current file bytes. An attestation is not a signature, identity proof, or statement about a deployed system.

## Continue with contracts

Use the [configuration guide](CONFIGURATION.md) for repository defaults, the [schema catalog](SCHEMAS.md) for accepted contract versions, and the [command-line interface](CLI.md) for stable exit behavior. A nonzero review finding is evidence for a human reviewer; it is not an automated deployment decision or runtime security conclusion.
