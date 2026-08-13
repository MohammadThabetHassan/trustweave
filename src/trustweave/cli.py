"""Command-line interface for TrustWeave's local security evidence workflow."""

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence
from pathlib import Path

from trustweave.engine import build_bundle
from trustweave.evidence import build_attestation, verify_attestation
from trustweave.io import load_document, read_json, write_json, write_text
from trustweave.models import ValidationError, parse_manifest, parse_policy
from trustweave.report import render_report
from trustweave.scenarios import parse_scenarios, run_scenarios

BUNDLE_FILE = "agent-security-bundle.json"
TEST_RESULTS_FILE = "security-test-results.json"
ATTESTATION_FILE = "attestation.json"
REPORT_FILE = "report.md"


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
        raise AssertionError(f"Unexpected command: {args.command}")
    except ValidationError as error:
        print(f"Validation error: {error}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
