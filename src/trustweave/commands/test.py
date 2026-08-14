"""Safe synthetic testing, explanation, and local trace-review commands."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from trustweave.commands._shared import (
    EXIT_REVIEW,
    TEST_RESULTS_FILE,
    TRACE_REVIEW_FILE,
    TRACE_REVIEW_REPORT_FILE,
    configured_paths,
)
from trustweave.engine import explain_policy_decision
from trustweave.io import load_document, read_json, write_json, write_text
from trustweave.models import parse_manifest, parse_policy, validate_capability_pattern
from trustweave.report import render_trace_review_report
from trustweave.scenarios import explain_scenario, parse_scenarios, run_scenarios
from trustweave.trace_review import review_trace


def register(subcommands: Any) -> None:
    """Register safe synthetic-test, explanation, and trace-review commands."""

    test = subcommands.add_parser("test", help="Run safe synthetic policy regression scenarios.")
    test.add_argument("--policy", type=Path, help="Path to a policy JSON or safe YAML file.")
    test.add_argument(
        "--scenarios", type=Path, help="Path to a scenario-pack JSON or safe YAML file."
    )
    test.add_argument("--output-dir", type=Path, help="Artifact directory.")
    test.add_argument("--config", type=Path, help="Explicit local trustweave.toml path.")

    explain = subcommands.add_parser(
        "explain", help="Explain one cited synthetic scenario without executing an agent."
    )
    explain.add_argument(
        "--scenarios", type=Path, required=True, help="Scenario-pack JSON or safe YAML."
    )
    explain.add_argument("--scenario-id", required=True, help="Synthetic scenario identifier.")

    why = subcommands.add_parser(
        "why", help="Explain a local policy decision for supplied declared synthetic labels."
    )
    why.add_argument("--policy", type=Path, required=True, help="Policy JSON or safe YAML file.")
    why.add_argument("--source-trust", required=True, help="Declared source trust label.")
    why.add_argument("--tool-action-class", required=True, help="Declared tool action class.")
    why.add_argument(
        "--source-data-classification", help="Optional declared source classification."
    )
    why.add_argument(
        "--tool-capability",
        action="append",
        default=[],
        help="Optional exact declared tool capability; repeat for multiple capabilities.",
    )
    why.add_argument("--source-identifier", default="synthetic-source")
    why.add_argument("--tool-identifier", default="synthetic-tool")
    why.add_argument("--purpose-tag", default="synthetic")

    trace_review = subcommands.add_parser(
        "trace-review",
        help="Review local trace metadata against declared flows without executing an agent.",
    )
    trace_review.add_argument(
        "--manifest", type=Path, required=True, help="Agent manifest JSON or safe YAML file."
    )
    trace_review.add_argument(
        "--policy", type=Path, required=True, help="Policy JSON or safe YAML file."
    )
    trace_review.add_argument(
        "--trace", type=Path, required=True, help="Local trace JSON file to review."
    )
    trace_review.add_argument(
        "--output-dir", type=Path, default=Path("artifacts"), help="Artifact directory."
    )
    trace_review.add_argument(
        "--exit-on-review", action="store_true", help="Return status 1 when the trace has findings."
    )


def handle(args: argparse.Namespace, generated_at: str) -> tuple[str, int]:
    """Execute one safe synthetic, explanation, or trace-review operation."""

    if args.command == "test":
        output_dir = args.output_dir
        if args.config is None and args.policy is not None and args.scenarios is not None:
            output_dir = output_dir or Path("artifacts")
        paths = configured_paths(
            args.config,
            {"policy": args.policy, "scenarios": args.scenarios, "output_dir": output_dir},
        )
        policy = parse_policy(load_document(paths["policy"]))
        scenarios = parse_scenarios(load_document(paths["scenarios"]))
        result = run_scenarios(policy, scenarios, generated_at)
        path = write_json(paths["output_dir"] / TEST_RESULTS_FILE, result)
        status = str(result["summary"]["status"])
        return f"Wrote synthetic test results ({status}): {path}", 0 if status == "passed" else 1
    if args.command == "explain":
        scenarios = parse_scenarios(load_document(args.scenarios))
        return explain_scenario(scenarios, args.scenario_id), 0
    if args.command == "why":
        policy = parse_policy(load_document(args.policy))
        capabilities = tuple(
            validate_capability_pattern(capability, "why.tool_capability", allow_namespace=False)
            for capability in args.tool_capability
        )
        explanation = explain_policy_decision(
            policy,
            args.source_trust,
            args.tool_action_class,
            args.source_data_classification,
            capabilities,
            args.source_identifier,
            args.tool_identifier,
            args.purpose_tag,
        )
        return json.dumps(explanation, sort_keys=True, separators=(",", ":")), 0
    if args.command == "trace-review":
        manifest = parse_manifest(load_document(args.manifest))
        policy = parse_policy(load_document(args.policy))
        review = review_trace(manifest, policy, read_json(args.trace), generated_at)
        json_path = write_json(args.output_dir / TRACE_REVIEW_FILE, review)
        markdown_path = write_text(
            args.output_dir / TRACE_REVIEW_REPORT_FILE, render_trace_review_report(review)
        )
        has_findings = int(review["summary"]["review_findings"]) > 0
        code = EXIT_REVIEW if args.exit_on_review and has_findings else 0
        return f"Wrote trace review: {json_path} and {markdown_path}", code
    raise RuntimeError(f"Unsupported test command: {args.command}")
