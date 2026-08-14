# Command-Line Interface

The `trustweave` command line is a **local file-oriented interface**. It accepts explicit inputs, writes deterministic artifacts, and uses stable exit codes. It does not execute an agent or a supplied tool configuration, invoke a model, contact a server, or authenticate with an external service.

## Discover commands from the parser

The top-level command reference is generated from the authoritative argument parser at build time in the repository. This prevents manual command lists from drifting after CLI changes.

```bash
python scripts/generate_cli_help.py
trustweave --help
```

See the [generated CLI help](CLI_HELP.md) for the exact current top-level parser output. The comprehensive command-by-command guide is maintained in the [repository CLI reference](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/CLI_REFERENCE.md).

## Exit behavior

| Exit code | Meaning |
|---:|---|
| `0` | The local command completed without an explicitly requested review failure. |
| `1` | A synthetic expectation failed, integrity verification failed, or an explicit review gate found a review finding. |
| `2` | The supplied command syntax, input, provenance value, or evidence contract is invalid. |
| `3` | A local input or output could not be safely read or written. |
| `4` | An unexpected internal failure occurred. |

Expected failures are written to standard error without a traceback. Prepend `--debug` to inspect an exception while diagnosing local development or integration issues.

## Reproducibility

Artifact-producing commands accept `--generated-at` with an ISO 8601 timestamp and UTC offset. If omitted, an application boundary may provide `SOURCE_DATE_EPOCH`; otherwise the current UTC time is used. The value documents artifact generation provenance only. It does not make a runtime claim or create authenticated provenance.

Read the [reproducibility contract](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/REPRODUCIBILITY.md) before relying on an artifact comparison or attestation verification result.
