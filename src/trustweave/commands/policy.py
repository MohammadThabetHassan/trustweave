"""Static declared-policy review command."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from trustweave.commands._shared import (
    EXIT_REVIEW,
    POLICY_REVIEW_FILE,
    POLICY_REVIEW_REPORT_FILE,
    configured_paths,
)
from trustweave.io import load_document, write_json, write_text
from trustweave.models import parse_policy
from trustweave.policy_review import review_policy
from trustweave.report import render_policy_review_report


def register(subcommands: Any) -> None:
    """Register static deterministic policy review."""

    policy_check = subcommands.add_parser(
        "policy-check", help="Review deterministic policy structure without executing a runtime."
    )
    policy_check.add_argument("--policy", type=Path, help="Policy JSON or safe YAML file.")
    policy_check.add_argument("--output-dir", type=Path, help="Artifact directory.")
    policy_check.add_argument("--config", type=Path, help="Explicit local trustweave.toml path.")
    policy_check.add_argument(
        "--coverage",
        action="store_true",
        help="Include deterministic rule reachability and contradiction diagnostics.",
    )
    policy_check.add_argument(
        "--exit-on-review",
        action="store_true",
        help="Return status 1 when the policy produces any review finding.",
    )


def handle(args: argparse.Namespace, generated_at: str) -> tuple[str, int]:
    """Create local policy-review evidence from one declared policy."""

    output_dir = args.output_dir
    if args.config is None and args.policy is not None:
        output_dir = output_dir or Path("artifacts")
    paths = configured_paths(args.config, {"policy": args.policy, "output_dir": output_dir})
    policy = parse_policy(load_document(paths["policy"]))
    review = review_policy(policy, generated_at, include_coverage=args.coverage)
    json_path = write_json(paths["output_dir"] / POLICY_REVIEW_FILE, review)
    markdown_path = write_text(
        paths["output_dir"] / POLICY_REVIEW_REPORT_FILE, render_policy_review_report(review)
    )
    has_findings = int(review["summary"]["review_findings"]) > 0
    code = EXIT_REVIEW if args.exit_on_review and has_findings else 0
    return f"Wrote policy review: {json_path} and {markdown_path}", code
