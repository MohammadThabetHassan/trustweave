"""Configured local CI evidence coordination command."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

from trustweave.commands._shared import (
    ATTESTATION_FILE,
    BUNDLE_FILE,
    EXIT_REVIEW,
    POLICY_REVIEW_FILE,
    POLICY_REVIEW_REPORT_FILE,
    REPORT_FILE,
    TEST_RESULTS_FILE,
    configured_paths,
)
from trustweave.engine import build_bundle
from trustweave.evidence import build_attestation
from trustweave.io import load_document, read_json, write_json, write_text
from trustweave.models import parse_manifest, parse_policy
from trustweave.policy_review import review_policy
from trustweave.report import render_policy_review_report, render_report
from trustweave.scenarios import parse_scenarios, run_scenarios


def register(subcommands: Any) -> None:
    """Register the bounded configured local evidence workflow."""

    ci = subcommands.add_parser(
        "ci",
        help=(
            "Run the configured local evidence workflow without executing an agent or "
            "contacting services."
        ),
    )
    ci.add_argument("--config", type=Path, help="Explicit local trustweave.toml path.")
    ci.add_argument(
        "--output-dir", type=Path, help="Override the configured local artifact directory."
    )
    ci.add_argument(
        "--source-revision",
        default=os.environ.get("GITHUB_SHA", "local-uncommitted"),
        help="Source revision recorded in the local evidence attestation.",
    )
    ci.add_argument(
        "--coverage", action="store_true", help="Include policy rule coverage diagnostics."
    )
    ci.add_argument(
        "--exit-on-review",
        action="store_true",
        help="Return status 1 when policy review findings exist.",
    )


def handle(args: argparse.Namespace, generated_at: str) -> tuple[str, int]:
    """Create bounded local CI evidence from declared project configuration only."""

    paths = configured_paths(
        args.config,
        {"manifest": None, "policy": None, "scenarios": None, "output_dir": args.output_dir},
    )
    manifest = parse_manifest(load_document(paths["manifest"]))
    policy = parse_policy(load_document(paths["policy"]))
    scenarios = parse_scenarios(load_document(paths["scenarios"]))
    bundle_path = write_json(
        paths["output_dir"] / BUNDLE_FILE, build_bundle(manifest, policy, generated_at)
    )
    test_results = run_scenarios(policy, scenarios, generated_at)
    test_path = write_json(paths["output_dir"] / TEST_RESULTS_FILE, test_results)
    review = review_policy(policy, generated_at, include_coverage=args.coverage)
    policy_path = write_json(paths["output_dir"] / POLICY_REVIEW_FILE, review)
    write_text(paths["output_dir"] / POLICY_REVIEW_REPORT_FILE, render_policy_review_report(review))
    attestation_path = write_json(
        paths["output_dir"] / ATTESTATION_FILE,
        build_attestation(
            bundle_path, test_path, source_revision=args.source_revision, generated_at=generated_at
        ),
    )
    report_path = write_text(
        paths["output_dir"] / REPORT_FILE,
        render_report(read_json(bundle_path), read_json(test_path), read_json(attestation_path)),
    )
    test_failed = str(test_results["summary"]["status"]) != "passed"
    review_required = int(review["summary"]["review_findings"]) > 0
    code = EXIT_REVIEW if test_failed or (args.exit_on_review and review_required) else 0
    return (
        f"Wrote local CI evidence: {bundle_path}, {test_path}, {policy_path}, "
        f"{attestation_path}, and {report_path}",
        code,
    )
