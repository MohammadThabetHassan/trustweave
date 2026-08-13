"""Command-line interface for TrustWeave's local security evidence workflow."""

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence
from pathlib import Path

from trustweave.diff import diff_bundles
from trustweave.engine import build_bundle
from trustweave.evidence import build_attestation, verify_attestation
from trustweave.framework_import import SUPPORTED_FRAMEWORKS, normalize_framework_declaration
from trustweave.io import load_document, read_json, write_json, write_text
from trustweave.mcp_import import build_manifest_scaffold, normalize_mcp_tools_list
from trustweave.mcp_profile import parse_mcp_profile, review_mcp_profile
from trustweave.models import ValidationError, parse_manifest, parse_policy
from trustweave.policy_review import review_policy
from trustweave.report import (
    render_diff_report,
    render_mcp_profile_review_report,
    render_policy_review_report,
    render_report,
    render_trace_review_report,
)
from trustweave.sarif import build_sarif
from trustweave.scenarios import explain_scenario, parse_scenarios, run_scenarios
from trustweave.trace_review import review_trace

BUNDLE_FILE = "agent-security-bundle.json"
TEST_RESULTS_FILE = "security-test-results.json"
ATTESTATION_FILE = "attestation.json"
REPORT_FILE = "report.md"
DIFF_FILE = "bundle-diff.json"
DIFF_REPORT_FILE = "bundle-diff.md"
POLICY_REVIEW_FILE = "policy-review.json"
POLICY_REVIEW_REPORT_FILE = "policy-review.md"
TRACE_REVIEW_FILE = "trace-review.json"
TRACE_REVIEW_REPORT_FILE = "trace-review.md"
MCP_PROFILE_REVIEW_FILE = "mcp-profile-review.json"
MCP_PROFILE_REVIEW_REPORT_FILE = "mcp-profile-review.md"
MCP_TOOL_INVENTORY_FILE = "mcp-tool-inventory.json"
MCP_MANIFEST_SCAFFOLD_FILE = "mcp-manifest-scaffold.json"
FRAMEWORK_INVENTORY_FILE = "framework-inventory.json"
SARIF_FILE = "trustweave.sarif"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustweave",
        description="Local-first security build evidence for declared AI agent trust boundaries.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser(
        "scan", help="Validate a manifest and write an Agent Security Bundle."
    )
    scan.add_argument(
        "--manifest", type=Path, required=True, help="Path to a manifest JSON or safe YAML file."
    )
    scan.add_argument(
        "--policy", type=Path, required=True, help="Path to a policy JSON or safe YAML file."
    )
    scan.add_argument(
        "--output-dir", type=Path, default=Path("artifacts"), help="Artifact directory."
    )

    test = subcommands.add_parser("test", help="Run safe synthetic policy regression scenarios.")
    test.add_argument(
        "--policy", type=Path, required=True, help="Path to a policy JSON or safe YAML file."
    )
    test.add_argument(
        "--scenarios",
        type=Path,
        required=True,
        help="Path to a scenario-pack JSON or safe YAML file.",
    )
    test.add_argument(
        "--output-dir", type=Path, default=Path("artifacts"), help="Artifact directory."
    )

    explain = subcommands.add_parser(
        "explain", help="Explain one cited synthetic scenario without executing an agent."
    )
    explain.add_argument(
        "--scenarios", type=Path, required=True, help="Scenario-pack JSON or safe YAML."
    )
    explain.add_argument("--scenario-id", required=True, help="Synthetic scenario identifier.")

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

    verify = subcommands.add_parser("verify", help="Verify the attestation's local hash chain.")
    verify.add_argument("--attestation", type=Path, required=True, help="Attestation JSON file.")

    diff = subcommands.add_parser(
        "diff", help="Compare two generated Agent Security Bundles without executing an agent."
    )
    diff.add_argument("--base", type=Path, required=True, help="Base Agent Security Bundle JSON.")
    diff.add_argument("--head", type=Path, required=True, help="Head Agent Security Bundle JSON.")
    diff.add_argument(
        "--output-dir", type=Path, default=Path("artifacts"), help="Artifact directory."
    )

    policy_check = subcommands.add_parser(
        "policy-check", help="Review deterministic policy structure without executing a runtime."
    )
    policy_check.add_argument(
        "--policy", type=Path, required=True, help="Policy JSON or safe YAML file."
    )
    policy_check.add_argument(
        "--output-dir", type=Path, default=Path("artifacts"), help="Artifact directory."
    )
    policy_check.add_argument(
        "--exit-on-review",
        action="store_true",
        help="Return status 1 when the policy produces any review finding.",
    )

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
        "--exit-on-review",
        action="store_true",
        help="Return status 1 when the trace produces any review finding.",
    )

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
        help="Return status 1 when the profile produces any review finding.",
    )

    sarif = subcommands.add_parser(
        "sarif",
        help="Export existing local review artifacts as deterministic SARIF 2.1.0 evidence.",
    )
    sarif.add_argument("--policy-review", type=Path, help="Policy-review JSON artifact.")
    sarif.add_argument("--diff", type=Path, help="Bundle-diff JSON artifact.")
    sarif.add_argument("--trace-review", type=Path, help="Trace-review JSON artifact.")
    sarif.add_argument("--mcp-profile-review", type=Path, help="MCP-profile-review JSON artifact.")
    sarif.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts") / SARIF_FILE,
        help="Local SARIF output path.",
    )

    return parser


def _scan(manifest_path: Path, policy_path: Path, output_dir: Path) -> str:
    manifest = parse_manifest(load_document(manifest_path))
    policy = parse_policy(load_document(policy_path))
    path = write_json(output_dir / BUNDLE_FILE, build_bundle(manifest, policy))
    return f"Wrote Agent Security Bundle: {path}"


def _test(policy_path: Path, scenario_path: Path, output_dir: Path) -> tuple[str, int]:
    policy = parse_policy(load_document(policy_path))
    scenarios = parse_scenarios(load_document(scenario_path))
    result = run_scenarios(policy, scenarios)
    path = write_json(output_dir / TEST_RESULTS_FILE, result)
    status = str(result["summary"]["status"])
    return f"Wrote synthetic test results ({status}): {path}", 0 if status == "passed" else 1


def _explain(scenario_path: Path, scenario_id: str) -> str:
    scenarios = parse_scenarios(load_document(scenario_path))
    return explain_scenario(scenarios, scenario_id)


def _attest(output_dir: Path, source_revision: str) -> str:
    attestation = build_attestation(
        output_dir / BUNDLE_FILE, output_dir / TEST_RESULTS_FILE, source_revision=source_revision
    )
    path = write_json(output_dir / ATTESTATION_FILE, attestation)
    return f"Wrote local evidence attestation: {path}"


def _report(output_dir: Path) -> str:
    report = render_report(
        read_json(output_dir / BUNDLE_FILE),
        read_json(output_dir / TEST_RESULTS_FILE),
        read_json(output_dir / ATTESTATION_FILE),
    )
    path = write_text(output_dir / REPORT_FILE, report)
    return f"Wrote Markdown report: {path}"


def _diff(base_path: Path, head_path: Path, output_dir: Path) -> str:
    diff = diff_bundles(read_json(base_path), read_json(head_path))
    json_path = write_json(output_dir / DIFF_FILE, diff)
    markdown_path = write_text(output_dir / DIFF_REPORT_FILE, render_diff_report(diff))
    return f"Wrote bundle diff: {json_path} and {markdown_path}"


def _policy_check(policy_path: Path, output_dir: Path, exit_on_review: bool) -> tuple[str, int]:
    policy = parse_policy(load_document(policy_path))
    review = review_policy(policy)
    json_path = write_json(output_dir / POLICY_REVIEW_FILE, review)
    markdown_path = write_text(
        output_dir / POLICY_REVIEW_REPORT_FILE, render_policy_review_report(review)
    )
    has_findings = int(review["summary"]["review_findings"]) > 0
    code = 1 if exit_on_review and has_findings else 0
    return f"Wrote policy review: {json_path} and {markdown_path}", code


def _trace_review(
    manifest_path: Path,
    policy_path: Path,
    trace_path: Path,
    output_dir: Path,
    exit_on_review: bool,
) -> tuple[str, int]:
    manifest = parse_manifest(load_document(manifest_path))
    policy = parse_policy(load_document(policy_path))
    review = review_trace(manifest, policy, read_json(trace_path))
    json_path = write_json(output_dir / TRACE_REVIEW_FILE, review)
    markdown_path = write_text(
        output_dir / TRACE_REVIEW_REPORT_FILE, render_trace_review_report(review)
    )
    has_findings = int(review["summary"]["review_findings"]) > 0
    code = 1 if exit_on_review and has_findings else 0
    return f"Wrote trace review: {json_path} and {markdown_path}", code


def _sarif(
    policy_review_path: Path | None,
    diff_path: Path | None,
    trace_review_path: Path | None,
    mcp_profile_review_path: Path | None,
    output_path: Path,
) -> str:
    selected_paths = {
        "policy": policy_review_path,
        "diff": diff_path,
        "trace": trace_review_path,
        "mcp": mcp_profile_review_path,
    }
    reviews = {
        kind: (path.as_posix(), read_json(path))
        for kind, path in selected_paths.items()
        if path is not None
    }
    path = write_json(output_path, build_sarif(reviews))
    return f"Wrote local SARIF evidence: {path}"


def _framework_import(framework: str, input_path: Path, output_dir: Path) -> str:
    inventory = normalize_framework_declaration(framework, load_document(input_path))
    path = write_json(output_dir / FRAMEWORK_INVENTORY_FILE, inventory)
    return f"Wrote local framework inventory: {path}"


def _mcp_scaffold(inventory_path: Path, output_dir: Path) -> str:
    path = write_json(
        output_dir / MCP_MANIFEST_SCAFFOLD_FILE, build_manifest_scaffold(read_json(inventory_path))
    )
    return f"Wrote reviewer-required MCP manifest scaffold: {path}"


def _mcp_import(tool_list_path: Path, output_dir: Path) -> str:
    inventory = normalize_mcp_tools_list(load_document(tool_list_path))
    path = write_json(output_dir / MCP_TOOL_INVENTORY_FILE, inventory)
    return f"Wrote local MCP tool inventory: {path}"


def _mcp_profile_check(
    manifest_path: Path, profile_path: Path, output_dir: Path, exit_on_review: bool
) -> tuple[str, int]:
    manifest = parse_manifest(load_document(manifest_path))
    profile = parse_mcp_profile(load_document(profile_path))
    review = review_mcp_profile(profile, manifest)
    json_path = write_json(output_dir / MCP_PROFILE_REVIEW_FILE, review)
    markdown_path = write_text(
        output_dir / MCP_PROFILE_REVIEW_REPORT_FILE, render_mcp_profile_review_report(review)
    )
    has_findings = int(review["summary"]["review_findings"]) > 0
    code = 1 if exit_on_review and has_findings else 0
    return f"Wrote MCP profile review: {json_path} and {markdown_path}", code


def main(argv: Sequence[str] | None = None) -> int:
    """Run the TrustWeave CLI and return an actionable status code."""

    args = _parser().parse_args(argv)
    try:
        if args.command == "scan":
            print(_scan(args.manifest, args.policy, args.output_dir))
            return 0
        if args.command == "test":
            message, code = _test(args.policy, args.scenarios, args.output_dir)
            print(message)
            return code
        if args.command == "explain":
            print(_explain(args.scenarios, args.scenario_id))
            return 0
        if args.command == "attest":
            print(_attest(args.output_dir, args.source_revision))
            return 0
        if args.command == "report":
            print(_report(args.output_dir))
            return 0
        if args.command == "verify":
            valid, message = verify_attestation(read_json(args.attestation))
            print(message)
            return 0 if valid else 1
        if args.command == "diff":
            print(_diff(args.base, args.head, args.output_dir))
            return 0
        if args.command == "policy-check":
            message, code = _policy_check(args.policy, args.output_dir, args.exit_on_review)
            print(message)
            return code
        if args.command == "trace-review":
            message, code = _trace_review(
                args.manifest,
                args.policy,
                args.trace,
                args.output_dir,
                args.exit_on_review,
            )
            print(message)
            return code
        if args.command == "sarif":
            print(
                _sarif(
                    args.policy_review,
                    args.diff,
                    args.trace_review,
                    args.mcp_profile_review,
                    args.output,
                )
            )
            return 0
        if args.command == "framework-import":
            print(_framework_import(args.framework, args.input, args.output_dir))
            return 0
        if args.command == "mcp-scaffold":
            print(_mcp_scaffold(args.inventory, args.output_dir))
            return 0
        if args.command == "mcp-import":
            print(_mcp_import(args.tool_list, args.output_dir))
            return 0
        if args.command == "mcp-profile-check":
            message, code = _mcp_profile_check(
                args.manifest,
                args.profile,
                args.output_dir,
                args.exit_on_review,
            )
            print(message)
            return code
        raise AssertionError(f"Unexpected command: {args.command}")
    except ValidationError as error:
        print(f"Validation error: {error}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
