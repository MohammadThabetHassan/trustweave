"""Local framework and MCP declaration import commands."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from trustweave.commands._shared import (
    EXIT_REVIEW,
    FRAMEWORK_INVENTORY_FILE,
    MCP_MANIFEST_SCAFFOLD_FILE,
    MCP_PROFILE_REVIEW_FILE,
    MCP_PROFILE_REVIEW_REPORT_FILE,
    MCP_TOOL_INVENTORY_FILE,
)
from trustweave.framework_import import SUPPORTED_FRAMEWORKS, normalize_framework_declaration
from trustweave.io import load_document, read_json, write_json, write_text
from trustweave.mcp_import import build_manifest_scaffold, normalize_mcp_tools_list
from trustweave.mcp_profile import parse_mcp_profile, review_mcp_profile
from trustweave.models import parse_manifest
from trustweave.report import render_mcp_profile_review_report


def register(subcommands: Any) -> None:
    """Register non-executing framework and MCP declaration commands."""

    framework_import = subcommands.add_parser(
        "framework-import",
        help="Normalize a local framework declaration without importing or running its framework.",
    )
    framework_import.add_argument(
        "--framework", choices=sorted(SUPPORTED_FRAMEWORKS), required=True
    )
    framework_import.add_argument(
        "--input", type=Path, required=True, help="Local declaration snapshot."
    )
    framework_import.add_argument(
        "--output-dir", type=Path, default=Path("artifacts"), help="Artifact directory."
    )

    mcp_scaffold = subcommands.add_parser(
        "mcp-scaffold", help="Create a reviewer-required manifest draft from a local MCP inventory."
    )
    mcp_scaffold.add_argument(
        "--inventory", type=Path, required=True, help="MCP tool inventory JSON."
    )
    mcp_scaffold.add_argument(
        "--output-dir", type=Path, default=Path("artifacts"), help="Artifact directory."
    )

    mcp_import = subcommands.add_parser(
        "mcp-import", help="Normalize a local MCP tools/list snapshot without a server connection."
    )
    mcp_import.add_argument(
        "--tool-list", type=Path, required=True, help="Local MCP tools/list JSON."
    )
    mcp_import.add_argument(
        "--output-dir", type=Path, default=Path("artifacts"), help="Artifact directory."
    )

    mcp_profile = subcommands.add_parser(
        "mcp-profile-check",
        help="Review a local MCP metadata profile without connecting to a server.",
    )
    mcp_profile.add_argument(
        "--manifest", type=Path, required=True, help="Agent manifest JSON or safe YAML file."
    )
    mcp_profile.add_argument(
        "--profile",
        type=Path,
        required=True,
        help="Local MCP metadata profile JSON or safe YAML file.",
    )
    mcp_profile.add_argument(
        "--output-dir", type=Path, default=Path("artifacts"), help="Artifact directory."
    )
    mcp_profile.add_argument(
        "--exit-on-review",
        action="store_true",
        help="Return status 1 when the profile has findings.",
    )


def handle(args: argparse.Namespace, generated_at: str) -> tuple[str, int]:
    """Execute one local framework or MCP declaration operation."""

    if args.command == "framework-import":
        inventory = normalize_framework_declaration(args.framework, load_document(args.input))
        path = write_json(args.output_dir / FRAMEWORK_INVENTORY_FILE, inventory)
        return f"Wrote local framework inventory: {path}", 0
    if args.command == "mcp-scaffold":
        path = write_json(
            args.output_dir / MCP_MANIFEST_SCAFFOLD_FILE,
            build_manifest_scaffold(read_json(args.inventory)),
        )
        return f"Wrote reviewer-required MCP manifest scaffold: {path}", 0
    if args.command == "mcp-import":
        inventory = normalize_mcp_tools_list(load_document(args.tool_list))
        path = write_json(args.output_dir / MCP_TOOL_INVENTORY_FILE, inventory)
        return f"Wrote local MCP tool inventory: {path}", 0
    if args.command == "mcp-profile-check":
        manifest = parse_manifest(load_document(args.manifest))
        profile = parse_mcp_profile(load_document(args.profile))
        review = review_mcp_profile(profile, manifest, generated_at)
        json_path = write_json(args.output_dir / MCP_PROFILE_REVIEW_FILE, review)
        markdown_path = write_text(
            args.output_dir / MCP_PROFILE_REVIEW_REPORT_FILE,
            render_mcp_profile_review_report(review),
        )
        has_findings = int(review["summary"]["review_findings"]) > 0
        code = EXIT_REVIEW if args.exit_on_review and has_findings else 0
        return f"Wrote MCP profile review: {json_path} and {markdown_path}", code
    raise RuntimeError(f"Unsupported importer command: {args.command}")
