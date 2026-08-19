# Compatibility Contract

## Authority and scope

The authoritative compatibility data is [`docs/contracts/compatibility-v1.json`](contracts/compatibility-v1.json), versioned as `trustweave.dev/compatibility/v1alpha1`. This guide is a readable rendering of that versioned source. It covers only TrustWeave’s local package and documented evidence formats; it does not assert compatibility with a live agent runtime, MCP server, external framework SDK, hosted code-scanning service, or third-party deployment.

## Python and platform support

| Area | Current contract |
| --- | --- |
| Minimum Python | Python **3.11** (`requires-python = ">=3.11"`). |
| Package classifiers | Python 3.11, 3.12, and 3.13. |
| Hosted compatibility evidence | Python 3.11 and 3.13 on Ubuntu, macOS, and Windows. |
| Local release verification | A clean isolated environment verifies package installation, console/module CLI behavior, and packaged schemas. |

## Public command contract

TrustWeave supports both `trustweave` and `python -m trustweave`. The command parser is the authoritative public command surface. Its top-level command names are covered by a compatibility validator rather than copied into untested documentation.

| Exit code | Meaning |
| ---: | --- |
| `0` | Successful local command completion. |
| `1` | Review-required result when a command explicitly requests review-gate behavior. |
| `2` | Invalid input, configuration, or command syntax. |
| `3` | Local input or output failure. |
| `4` | Unexpected internal error. |

The `--version` and `-V` flags print the authoritative package version and exit successfully. They do not discover configuration, write files, or access a network.

## Artifact writer and reader behavior

| Artifact family | Current writer | Historical behavior |
| --- | --- | --- |
| Agent Security Bundle | `trustweave.dev/bundle/v1alpha2` | Bundle comparison reads bounded `v1alpha1` and `v1alpha2` inputs. |
| Bundle diff | `trustweave.dev/bundle-diff/v1alpha3` | Risk normalization reads bounded `v1alpha1`, `v1alpha2`, and `v1alpha3` diff inputs. |
| Risk review | `trustweave.dev/risk-review/v1alpha2` | The historical `v1alpha1` schema remains a bounded historical reader case; create current evidence for new decisions. |
| Risk baseline and suppressions | `trustweave.dev/risk-baseline/v1alpha2` and `trustweave.dev/risk-suppressions/v1alpha2` | `v1alpha1` decision documents require explicit migration and are not silently reinterpreted. |
| Local attestation | `trustweave.dev/attestation/v1alpha3` | The verifier retains documented local `v1alpha1`, `v1alpha2`, and `v1alpha3` readers. |
| Synthetic test results | `trustweave.dev/test-results/v1alpha1` | Current contract. |

All runtime-emitted versioned artifacts have published schemas, and the installed wheel must carry byte-identical schema resources. See the [schema and compatibility policy](SCHEMA_AND_COMPATIBILITY.md) and [schema catalog](SCHEMA_CATALOG.md) for complete structural contracts.

## Migration rule

Regenerate evidence with the current CLI rather than editing a historical `schema_version` string. **Historical local evidence remains readable only** where a bounded reader and fixture prove the documented behavior. A preserved historical reader demonstrates bounded compatibility only; it does not mean every old artifact gains current semantics or can create current reviewer decisions.

## Intentional limits

TrustWeave reads supplied local declarations and pre-recorded metadata only. It does not execute agents, tools, application code, MCP servers, or models; contact remote systems; access credentials; upload results; or enforce runtime decisions. Compatibility language never expands this boundary.
