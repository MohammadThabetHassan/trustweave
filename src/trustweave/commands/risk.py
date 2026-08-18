"""Local deterministic risk lifecycle commands."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from trustweave.commands._shared import EXIT_REVIEW, RISK_REVIEW_FILE, RISK_REVIEW_REPORT_FILE
from trustweave.io import load_document, read_json, write_json, write_text
from trustweave.report import render_risk_review_report
from trustweave.risk import (
    VALID_SEVERITIES,
    create_baseline,
    review_risks,
    should_fail,
    validate_decision_document,
)


def register(subcommands: Any) -> None:
    """Register local baseline, suppression, and risk-review commands."""

    baseline = subcommands.add_parser(
        "baseline", help="Create or validate explicit local risk-baseline decisions."
    )
    baseline_commands = baseline.add_subparsers(dest="baseline_command", required=True)
    baseline_create = baseline_commands.add_parser(
        "create", help="Create an explicit baseline draft from active local risk-review findings."
    )
    baseline_create.add_argument(
        "--review", type=Path, required=True, help="Local risk-review JSON."
    )
    baseline_create.add_argument(
        "--reason", required=True, help="Explicit reviewer decision reason."
    )
    baseline_create.add_argument("--expires-at", required=True, help="ISO 8601 expiry timestamp.")
    baseline_create.add_argument(
        "--owner", required=True, help="Explicit local decision owner label."
    )
    baseline_create.add_argument(
        "--reference", help="Optional local ticket or reviewer reference identifier."
    )
    baseline_create.add_argument(
        "--output", type=Path, required=True, help="Baseline JSON output path."
    )
    baseline_validate = baseline_commands.add_parser(
        "validate", help="Validate one local risk-baseline JSON or safe YAML document."
    )
    baseline_validate.add_argument(
        "--input", type=Path, required=True, help="Local baseline document."
    )

    suppressions = subcommands.add_parser(
        "suppressions", help="Validate explicit local risk-suppression decisions."
    )
    suppressions_commands = suppressions.add_subparsers(dest="suppressions_command", required=True)
    suppressions_validate = suppressions_commands.add_parser(
        "validate", help="Validate one local risk-suppressions JSON or safe YAML document."
    )
    suppressions_validate.add_argument(
        "--input", type=Path, required=True, help="Local suppressions document."
    )

    risk_check = subcommands.add_parser(
        "risk-check",
        help="Evaluate local review findings against expiry-enforced baselines and suppressions.",
    )
    risk_check.add_argument(
        "--input",
        type=Path,
        action="append",
        required=True,
        help="Local review artifact JSON; repeat for multiple artifacts.",
    )
    risk_check.add_argument(
        "--baseline", type=Path, help="Optional local risk-baseline JSON or YAML."
    )
    risk_check.add_argument(
        "--suppressions", type=Path, help="Optional local risk-suppressions JSON or YAML."
    )
    risk_check.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts") / RISK_REVIEW_FILE,
        help="Local risk-review JSON output path.",
    )
    risk_check.add_argument(
        "--markdown-output",
        type=Path,
        help="Optional local Markdown summary path; defaults beside the JSON output.",
    )
    risk_check.add_argument(
        "--fail-on",
        choices=[*VALID_SEVERITIES, "none"],
        default="high",
        help="Return status 1 for active findings at or above this severity; defaults to high.",
    )


def handle(args: argparse.Namespace, generated_at: str) -> tuple[str, int]:
    """Execute one local risk lifecycle command."""

    if args.command == "baseline":
        if args.baseline_command == "create":
            baseline = create_baseline(
                read_json(args.review),
                args.reason,
                args.expires_at,
                owner=args.owner,
                created_at=generated_at,
                reference=args.reference,
            )
            path = write_json(args.output, baseline)
            return f"Wrote local risk baseline: {path}", 0
        validate_decision_document(load_document(args.input), "baseline")
        return f"Validated local risk baseline: {args.input}", 0
    if args.command == "suppressions":
        validate_decision_document(load_document(args.input), "suppressions")
        return f"Validated local risk suppressions: {args.input}", 0
    if args.command == "risk-check":
        review = review_risks(
            [read_json(path) for path in args.input],
            baseline_document=load_document(args.baseline) if args.baseline else None,
            suppressions_document=load_document(args.suppressions) if args.suppressions else None,
            reviewed_at=generated_at,
            artifact_paths=[path.as_posix() for path in args.input],
        )
        path = write_json(args.output, review)
        markdown_path = write_text(
            args.markdown_output or args.output.with_name(RISK_REVIEW_REPORT_FILE),
            render_risk_review_report(review),
        )
        code = EXIT_REVIEW if should_fail(review, args.fail_on) else 0
        return f"Wrote local risk review: {path} and {markdown_path}", code
    raise RuntimeError(f"Unsupported risk command: {args.command}")
