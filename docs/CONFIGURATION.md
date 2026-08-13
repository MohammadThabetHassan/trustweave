# Local Configuration

`trustweave init` writes a starter `trustweave.toml` into an explicitly selected directory and refuses to overwrite an existing file. The starter document contains only local relative paths for a manifest, policy, scenario pack, and output directory.

```bash
trustweave init --directory .
```

The configuration parser is strict: it accepts only non-empty string values in `[tool.trustweave]` for `manifest`, `policy`, `scenarios`, and `output_dir`, and rejects unknown fields. It does not support remote includes, secret fields, environment harvesting, path execution, or network access.

```bash
trustweave config validate --config trustweave.toml
trustweave config show --config trustweave.toml
```

`config validate` reads and validates one explicit local TOML document without changing it. `config show` emits the validated values as deterministic JSON. Both commands default to `trustweave.toml` in the current directory when `--config` is omitted.

`scan`, `test`, and `policy-check` accept `--config PATH`. Their explicit command-line values take precedence. When a required path is absent, TrustWeave uses the explicit configuration file or walks upward from the current directory to find the nearest existing `trustweave.toml`. Relative configuration values are resolved from that configuration file’s directory. Discovery reads only local parent directories; it does not execute configuration, inspect a deployment, or contact a network service.

> Configuration selects local evidence inputs and outputs. It does not authenticate a policy, authorize an action, execute a tool, enforce a runtime control, or establish that a declared system is secure.
