"""Declared-manifest scan command."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from trustweave.bundles import validate_bundle
from trustweave.commands._shared import BUNDLE_FILE, configured_paths
from trustweave.engine import build_bundle
from trustweave.io import load_document, resolve_artifact_dir, write_json
from trustweave.models import parse_manifest, parse_policy


def register(subcommands: Any) -> None:
    """Register manifest scan evidence generation."""

    scan = subcommands.add_parser(
        "scan", help="Validate a manifest and write an Agent Security Bundle."
    )
    scan.add_argument("--manifest", type=Path, help="Path to a manifest JSON or safe YAML file.")
    scan.add_argument("--policy", type=Path, help="Path to a policy JSON or safe YAML file.")
    scan.add_argument("--output-dir", type=Path, help="Artifact directory.")
    scan.add_argument("--config", type=Path, help="Explicit local trustweave.toml path.")


def handle(args: argparse.Namespace, generated_at: str) -> tuple[str, int]:
    """Validate one manifest and write deterministic local bundle evidence."""

    output_dir = args.output_dir
    if args.config is None and args.manifest is not None and args.policy is not None:
        output_dir = output_dir or Path("artifacts")
    paths = configured_paths(
        args.config,
        {"manifest": args.manifest, "policy": args.policy, "output_dir": output_dir},
    )
    manifest = parse_manifest(load_document(paths["manifest"]))
    policy = parse_policy(load_document(paths["policy"]))
    bundle = build_bundle(manifest, policy, generated_at)
    # attest and diff both re-derive a bundle's findings before they will trust it. Scan
    # used to write whatever build_bundle returned, so a bundle those two commands refuse
    # was only discovered a command or two later, against coordinates inside a rendered
    # copy the user never wrote. Round-tripping here costs roughly 6x the build and
    # refuses with the identical message.
    validate_bundle(bundle, "bundle")
    path = write_json(resolve_artifact_dir(paths["output_dir"]) / BUNDLE_FILE, bundle)
    return f"Wrote Agent Security Bundle: {path}", 0
