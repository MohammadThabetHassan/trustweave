"""Local initialization, configuration, and packaged-schema commands."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from trustweave.config import init_project, load_project_config
from trustweave.schema_catalog import list_schema_names, read_schema


def register(subcommands: Any) -> None:
    """Register initialization, configuration, and schema subcommands."""

    init = subcommands.add_parser(
        "init", help="Create an opt-in local trustweave.toml template without overwriting files."
    )
    init.add_argument("--directory", type=Path, default=Path("."), help="Project directory.")

    config = subcommands.add_parser(
        "config", help="Validate or display explicit local TrustWeave project configuration."
    )
    config_commands = config.add_subparsers(dest="config_command", required=True)
    for name, help_text in (
        ("validate", "Validate one local trustweave.toml document."),
        ("show", "Print one validated local trustweave.toml document as JSON."),
    ):
        config_command = config_commands.add_parser(name, help=help_text)
        config_command.add_argument(
            "--config",
            type=Path,
            default=Path("trustweave.toml"),
            help="Local TOML configuration path.",
        )

    schema = subcommands.add_parser("schema", help="List or display checked-in local JSON Schemas.")
    schema_commands = schema.add_subparsers(dest="schema_command", required=True)
    schema_commands.add_parser("list", help="List checked-in schema filenames.")
    schema_show = schema_commands.add_parser("show", help="Print one checked-in schema document.")
    schema_show.add_argument("name", help="Exact schema filename from `trustweave schema list`.")


def handle(args: argparse.Namespace) -> tuple[str, int]:
    """Handle one parsed initialization, configuration, or schema command."""

    if args.command == "init":
        return f"Wrote local project configuration: {init_project(args.directory)}", 0
    if args.command == "config":
        if args.config_command == "validate":
            load_project_config(args.config)
            return f"Validated local project configuration: {args.config}", 0
        return json.dumps(
            load_project_config(args.config), sort_keys=True, separators=(",", ":")
        ), 0
    if args.command == "schema":
        if args.schema_command == "list":
            return "\n".join(list_schema_names()), 0
        return read_schema(args.name), 0
    raise RuntimeError(f"Unsupported configuration command: {args.command}")
