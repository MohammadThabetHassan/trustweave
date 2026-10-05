# Installation and five-minute local review

TrustWeave supports **Python 3.11 and later**. Every command reads local files and writes local
artifacts; nothing is executed and no network request is made.

## Install the published package

```shell
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip trustweave
trustweave --help
# Equivalent module invocation:
python -m trustweave --help
```

YAML parsing is optional. Install it only if your declarations use YAML:

```shell
python -m pip install 'trustweave[yaml]'
```

## Review the included example

The source tree contains a self-contained example. This workflow reads only checked-in files and
writes its artifacts under `artifacts/`.

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
trustweave attest --source-revision local --output-dir artifacts
trustweave report --output-dir artifacts
```

| Artifact | What it holds |
| --- | --- |
| `artifacts/agent-security-bundle.json` | The policy decision for every declared flow |
| `artifacts/security-test-results.json` | The results of the synthetic policy scenarios |
| `artifacts/report.md` | A readable summary of the findings and their limits |

Run `trustweave attest` once you have reviewed the source revision it should identify. To confirm
later that the files under review are the ones attested, pass all three paths:
`trustweave verify --attestation artifacts/attestation.json --bundle artifacts/agent-security-bundle.json --test-results artifacts/security-test-results.json`.
With the attestation alone, `verify` checks only the statement’s internal consistency. An
attestation is an integrity record, not a signature.

## Continue with contracts

The [configuration guide](CONFIGURATION.md) covers repository defaults, the
[schema catalog](SCHEMAS.md) the accepted contract versions, and the
[command-line interface](CLI.md) the exit codes. A nonzero exit on a finding is a signal for the
reviewer, not a deployment decision.
