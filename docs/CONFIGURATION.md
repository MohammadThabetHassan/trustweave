# Local Configuration

`trustweave init` writes a starter `trustweave.toml` into an explicitly selected directory and refuses to overwrite an existing file. The starter document contains only local relative paths for a manifest, policy, scenario pack, and output directory.

```bash
trustweave init --directory .
```

The configuration parser is strict: it accepts only non-empty string values in `[tool.trustweave]` for `manifest`, `policy`, `scenarios`, and `output_dir`, and rejects unknown fields. It does not support remote includes, secret fields, environment harvesting, automatic discovery, path execution, or network access.

The current command is intentionally opt-in and does not silently change existing command defaults. A future separately reviewed configuration orchestration layer may add explicit `--config`, controlled discovery, effective-configuration display, and a one-command workflow while preserving the same local-only boundary.
