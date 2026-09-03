"""Local evidence generation, verification, rendering, diff, and export commands."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

from trustweave.bundles import validate_bundle
from trustweave.commands._shared import (
    ATTESTATION_FILE,
    BUNDLE_FILE,
    DIFF_FILE,
    DIFF_REPORT_FILE,
    REPORT_FILE,
    SARIF_FILE,
    TEST_RESULTS_FILE,
    UNSIGNED_STATEMENT_FILE,
)
from trustweave.diff import diff_bundles
from trustweave.evidence import build_attestation, verify_attestation
from trustweave.io import read_json, write_json, write_text
from trustweave.report import render_diff_report, render_report
from trustweave.sarif import build_sarif
from trustweave.statement import build_unsigned_statement


def register(subcommands: Any) -> None:
    """Register evidence production, validation, and export commands."""

    attest = subcommands.add_parser("attest", help="Write a local hash-linked evidence statement.")
    attest.add_argument(
        "--output-dir", type=Path, default=Path("artifacts"), help="Artifact directory."
    )
    attest.add_argument(
        "--source-revision",
        default=os.environ.get("GITHUB_SHA", "local-uncommitted"),
        help="Source revision recorded in the local evidence statement.",
    )

    report = subcommands.add_parser(
        "report", help="Render a Markdown report from generated artifacts."
    )
    report.add_argument(
        "--output-dir", type=Path, default=Path("artifacts"), help="Artifact directory."
    )

    verify = subcommands.add_parser(
        "verify", help="Verify local attestation integrity and optionally supplied evidence files."
    )
    verify.add_argument("--attestation", type=Path, required=True, help="Attestation JSON file.")
    verify.add_argument(
        "--bundle", type=Path, help="Optional local bundle file for exact-file verification."
    )
    verify.add_argument(
        "--test-results",
        type=Path,
        help="Optional local test-results file for exact-file verification.",
    )

    diff = subcommands.add_parser(
        "diff", help="Compare two generated Agent Security Bundles without executing an agent."
    )
    diff.add_argument("--base", type=Path, required=True, help="Base Agent Security Bundle JSON.")
    diff.add_argument("--head", type=Path, required=True, help="Head Agent Security Bundle JSON.")
    diff.add_argument(
        "--output-dir", type=Path, default=Path("artifacts"), help="Artifact directory."
    )

    statement = subcommands.add_parser(
        "statement",
        help="Export an existing local attestation as an explicitly unsigned statement.",
    )
    statement.add_argument(
        "--attestation", type=Path, required=True, help="Local attestation JSON."
    )
    statement.add_argument(
        "--output-dir", type=Path, default=Path("artifacts"), help="Artifact directory."
    )

    sarif = subcommands.add_parser(
        "sarif",
        help="Export existing local review artifacts as deterministic SARIF 2.1.0 evidence.",
    )
    sarif.add_argument("--policy-review", type=Path, help="Policy-review JSON artifact.")
    sarif.add_argument("--diff", type=Path, help="Bundle-diff JSON artifact.")
    sarif.add_argument("--trace-review", type=Path, help="Trace-review JSON artifact.")
    sarif.add_argument("--mcp-profile-review", type=Path, help="MCP-profile-review JSON artifact.")
    sarif.add_argument("--risk-review", type=Path, help="Local risk-review JSON artifact.")
    sarif.add_argument(
        "--chain-review", type=Path, help="Local declared-chain review JSON artifact."
    )
    sarif.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts") / SARIF_FILE,
        help="Local SARIF output path.",
    )


def handle(args: argparse.Namespace, generated_at: str) -> tuple[str, int]:
    """Execute one local evidence command with no runtime execution or network activity."""

    if args.command == "attest":
        # Hashing binds bytes to bytes. It cannot tell that a finding was edited from
        # deny to allow, so re-derive the bundle's findings from the manifest and policy
        # it carries before signing anything over it.
        validate_bundle(read_json(args.output_dir / BUNDLE_FILE), "bundle")
        attestation = build_attestation(
            args.output_dir / BUNDLE_FILE,
            args.output_dir / TEST_RESULTS_FILE,
            source_revision=args.source_revision,
            generated_at=generated_at,
        )
        path = write_json(args.output_dir / ATTESTATION_FILE, attestation)
        return f"Wrote local evidence attestation: {path}", 0
    if args.command == "report":
        report = render_report(
            read_json(args.output_dir / BUNDLE_FILE),
            read_json(args.output_dir / TEST_RESULTS_FILE),
            read_json(args.output_dir / ATTESTATION_FILE),
        )
        path = write_text(args.output_dir / REPORT_FILE, report)
        return f"Wrote Markdown report: {path}", 0
    if args.command == "verify":
        valid, message = verify_attestation(
            read_json(args.attestation), args.bundle, args.test_results
        )
        return message, 0 if valid else 1
    if args.command == "diff":
        diff = diff_bundles(read_json(args.base), read_json(args.head), generated_at)
        json_path = write_json(args.output_dir / DIFF_FILE, diff)
        markdown_path = write_text(args.output_dir / DIFF_REPORT_FILE, render_diff_report(diff))
        return f"Wrote bundle diff: {json_path} and {markdown_path}", 0
    if args.command == "statement":
        path = write_json(
            args.output_dir / UNSIGNED_STATEMENT_FILE,
            build_unsigned_statement(read_json(args.attestation)),
        )
        return f"Wrote unsigned local statement: {path}", 0
    if args.command == "sarif":
        selected_paths = {
            "policy": args.policy_review,
            "diff": args.diff,
            "trace": args.trace_review,
            "mcp": args.mcp_profile_review,
            "risk": args.risk_review,
            "chain": args.chain_review,
        }
        reviews = {
            kind: (path.as_posix(), read_json(path))
            for kind, path in selected_paths.items()
            if path is not None
        }
        path = write_json(args.output, build_sarif(reviews))
        return f"Wrote local SARIF evidence: {path}", 0
    raise RuntimeError(f"Unsupported evidence command: {args.command}")
