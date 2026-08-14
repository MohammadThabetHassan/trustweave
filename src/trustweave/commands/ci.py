"""Configured local CI evidence coordination command."""

from __future__ import annotations

import argparse
import os
import shutil
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from trustweave.chain import render_chain_review, review_declared_chains
from trustweave.commands._shared import (
    ATTESTATION_FILE,
    BUNDLE_FILE,
    CHAIN_REVIEW_FILE,
    CHAIN_REVIEW_REPORT_FILE,
    EXIT_REVIEW,
    POLICY_REVIEW_FILE,
    POLICY_REVIEW_REPORT_FILE,
    REPORT_FILE,
    TEST_RESULTS_FILE,
    configured_paths,
)
from trustweave.config import find_project_config, load_project_config
from trustweave.engine import build_bundle
from trustweave.evidence import build_attestation
from trustweave.io import canonical_json, read_json, write_json, write_text
from trustweave.models import InputOutputError, ValidationError, parse_manifest, parse_policy
from trustweave.policy_review import review_policy
from trustweave.report import render_policy_review_report, render_report
from trustweave.risk import VALID_SEVERITIES
from trustweave.sarif import build_sarif
from trustweave.scenarios import parse_scenarios, run_scenarios

CI_SUMMARY_FILE = "ci-summary.json"
CI_SUMMARY_SCHEMA_VERSION = "trustweave.dev/ci-summary/v1alpha1"
DEFAULT_STAGES = ("scan", "scenarios", "policy_review", "attestation", "report", "summary")
CI_SUPPORTED_STAGES = frozenset({*DEFAULT_STAGES, "policy_coverage", "chain_review", "sarif"})
SEVERITY_RANK = {severity: index for index, severity in enumerate(VALID_SEVERITIES)}


def register(subcommands: Any) -> None:
    """Register the bounded configured local evidence workflow."""

    ci = subcommands.add_parser(
        "ci",
        help=(
            "Run configured local evidence stages without executing an agent or contacting "
            "services."
        ),
    )
    ci.add_argument("--config", type=Path, help="Explicit local trustweave.toml path.")
    ci.add_argument(
        "--no-config-discovery",
        action="store_true",
        help="Require --config instead of discovering trustweave.toml from the current directory.",
    )
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
        help="Return status 1 when a selected review stage reports any finding.",
    )
    ci.add_argument(
        "--fail-on",
        choices=[*VALID_SEVERITIES, "none"],
        help="Return status 1 for selected review findings at or above this severity.",
    )
    ci.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Render the final local CI summary as text, JSON, or Markdown.",
    )
    ci.add_argument("--quiet", action="store_true", help="Suppress the final CI summary message.")


def _config_path(args: argparse.Namespace) -> Path:
    """Resolve the one local configuration path without unbounded implicit discovery."""

    if args.config is not None:
        if not isinstance(args.config, Path):
            raise ValidationError("--config must identify a local configuration path")
        return args.config
    if args.no_config_discovery:
        raise ValidationError("--no-config-discovery requires an explicit --config path")
    return find_project_config(Path.cwd())


def _selected_stages(config: Mapping[str, object]) -> tuple[str, ...]:
    """Return declared stage order, preserving deterministic configuration order."""

    configured = config.get("enabled_stages")
    if configured is None:
        return DEFAULT_STAGES
    if not isinstance(configured, tuple) or not all(isinstance(stage, str) for stage in configured):
        raise ValidationError("tool.trustweave.enabled_stages must be a validated stage list")
    unsupported = sorted(set(configured) - CI_SUPPORTED_STAGES)
    if unsupported:
        raise ValidationError(
            "trustweave ci does not implement configured stages: " + ", ".join(unsupported)
        )
    return configured


def _required_paths(stages: Sequence[str]) -> set[str]:
    """Require only the declared local inputs needed by selected core stages."""

    required: set[str] = set()
    if "scan" in stages:
        required.update({"manifest", "policy"})
    if "scenarios" in stages:
        required.update({"policy", "scenarios"})
    if "policy_review" in stages:
        required.add("policy")
    if "chain_review" in stages:
        required.add("chain_manifest")
    return required


def _staged_sarif_path(config: Mapping[str, object], staging: Path) -> Path:
    """Return a configured SARIF path that cannot escape the staged artifact directory."""

    configured = config.get("sarif_output", "trustweave.sarif")
    if not isinstance(configured, str):
        raise ValidationError("tool.trustweave.sarif_output must be a local path string")
    path = Path(configured)
    if path.is_absolute() or ".." in path.parts:
        raise ValidationError(
            "tool.trustweave.sarif_output must remain within the CI artifact directory"
        )
    return staging / path


def _publish_directory(staging: Path, output: Path) -> None:
    """Atomically replace one artifact directory, restoring the prior directory on failure."""

    if output.exists() and not output.is_dir():
        raise InputOutputError(f"CI output path must be a directory: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    backup = output.parent / f".{output.name}.previous"
    if backup.exists():
        shutil.rmtree(backup)
    replaced = False
    try:
        if output.exists():
            output.replace(backup)
            replaced = True
        staging.replace(output)
    except OSError as error:
        if replaced and backup.exists() and not output.exists():
            backup.replace(output)
        raise InputOutputError(f"Could not publish CI artifacts to {output}: {error}") from error
    if backup.exists():
        shutil.rmtree(backup)


def _fail_on_findings(
    review: Mapping[str, Any] | None, threshold: str, exit_on_review: bool
) -> bool:
    """Evaluate the explicit local review gate without implying remediation or enforcement."""

    if review is None:
        return False
    findings = review.get("findings")
    if not isinstance(findings, list) or not findings:
        return False
    if exit_on_review:
        return True
    if threshold == "none":
        return False
    minimum = SEVERITY_RANK[threshold]
    return any(
        isinstance(finding, Mapping)
        and isinstance(finding.get("severity"), str)
        and finding["severity"] in SEVERITY_RANK
        and SEVERITY_RANK[finding["severity"]] <= minimum
        for finding in findings
    )


def _render_summary(summary: Mapping[str, Any], output_format: str) -> str:
    """Render a stable final coordinator summary without reading external state."""

    if output_format == "json":
        return canonical_json(summary).rstrip()
    if output_format == "markdown":
        artifacts = "\n".join(f"- `{name}`" for name in summary["artifacts"])
        return (
            "# TrustWeave Local CI Summary\n\n"
            f"**Status:** **{summary['status']}**  \n"
            f"**Generated at:** `{summary['generated_at']}`\n\n"
            "## Published artifacts\n\n"
            f"{artifacts}"
        )
    return "Wrote staged local CI evidence: " + ", ".join(summary["artifacts"])


def handle(args: argparse.Namespace, generated_at: str) -> tuple[str, int]:
    """Create configured local evidence and publish only a complete selected artifact set."""

    config_path = _config_path(args)
    config = load_project_config(config_path)
    stages = _selected_stages(config)
    required = _required_paths(stages)
    paths = configured_paths(
        config_path,
        {
            **{name: None for name in sorted(required)},
            "output_dir": args.output_dir,
        },
    )
    output_dir = paths["output_dir"]
    configured_threshold = config.get("failure_threshold", "none")
    if not isinstance(configured_threshold, str):
        raise ValidationError("tool.trustweave.failure_threshold must be a severity string")
    threshold = args.fail_on or configured_threshold

    with tempfile.TemporaryDirectory(prefix=".trustweave-ci-", dir=output_dir.parent) as temporary:
        staging = Path(temporary) / "artifacts"
        staging.mkdir()
        manifest = None
        policy = None
        bundle_path: Path | None = None
        test_path: Path | None = None
        attestation_path: Path | None = None
        policy_review: Mapping[str, Any] | None = None
        chain_review: Mapping[str, Any] | None = None
        artifacts: list[str] = []

        if "scan" in stages:
            manifest = parse_manifest(read_json(paths["manifest"]))
            policy = parse_policy(read_json(paths["policy"]))
            bundle_path = write_json(
                staging / BUNDLE_FILE, build_bundle(manifest, policy, generated_at)
            )
            artifacts.append(BUNDLE_FILE)
        if "scenarios" in stages:
            policy = policy or parse_policy(read_json(paths["policy"]))
            scenarios = parse_scenarios(read_json(paths["scenarios"]))
            test_path = write_json(
                staging / TEST_RESULTS_FILE, run_scenarios(policy, scenarios, generated_at)
            )
            artifacts.append(TEST_RESULTS_FILE)
        if "policy_review" in stages:
            policy = policy or parse_policy(read_json(paths["policy"]))
            policy_review = review_policy(
                policy, generated_at, include_coverage=args.coverage or "policy_coverage" in stages
            )
            write_json(staging / POLICY_REVIEW_FILE, policy_review)
            write_text(
                staging / POLICY_REVIEW_REPORT_FILE, render_policy_review_report(policy_review)
            )
            artifacts.extend((POLICY_REVIEW_FILE, POLICY_REVIEW_REPORT_FILE))
        if "chain_review" in stages:
            chain_review = review_declared_chains(read_json(paths["chain_manifest"]), generated_at)
            write_json(staging / CHAIN_REVIEW_FILE, chain_review)
            write_text(staging / CHAIN_REVIEW_REPORT_FILE, render_chain_review(chain_review))
            artifacts.extend((CHAIN_REVIEW_FILE, CHAIN_REVIEW_REPORT_FILE))
        if "sarif" in stages:
            sarif_reviews: dict[str, tuple[str, Mapping[str, Any]]] = {}
            if policy_review is not None:
                sarif_reviews["policy"] = (POLICY_REVIEW_FILE, policy_review)
            if chain_review is not None:
                sarif_reviews["chain"] = (CHAIN_REVIEW_FILE, chain_review)
            if not sarif_reviews:
                raise ValidationError(
                    "sarif stage requires at least one selected local review stage"
                )
            sarif_path = _staged_sarif_path(config, staging)
            write_json(sarif_path, build_sarif(sarif_reviews))
            artifacts.append(sarif_path.relative_to(staging).as_posix())
        if "attestation" in stages:
            if bundle_path is None or test_path is None:
                raise ValidationError(
                    "attestation stage requires selected scan and scenarios stages"
                )
            attestation_path = write_json(
                staging / ATTESTATION_FILE,
                build_attestation(
                    bundle_path,
                    test_path,
                    source_revision=args.source_revision,
                    generated_at=generated_at,
                ),
            )
            artifacts.append(ATTESTATION_FILE)
        if "report" in stages:
            if bundle_path is None or test_path is None or attestation_path is None:
                raise ValidationError(
                    "report stage requires selected scan, scenarios, and attestation stages"
                )
            write_text(
                staging / REPORT_FILE,
                render_report(
                    read_json(bundle_path), read_json(test_path), read_json(attestation_path)
                ),
            )
            artifacts.append(REPORT_FILE)

        test_failed = (
            test_path is not None
            and read_json(test_path).get("summary", {}).get("status") != "passed"
        )
        code = (
            EXIT_REVIEW
            if test_failed or _fail_on_findings(policy_review, threshold, args.exit_on_review)
            else 0
        )
        summary: dict[str, Any] = {
            "schema_version": CI_SUMMARY_SCHEMA_VERSION,
            "generated_at": generated_at,
            "status": "review_required" if code == EXIT_REVIEW else "clear",
            "stages": list(stages),
            "artifacts": sorted(artifacts),
            "limitations": [
                "This coordinator processes only supplied local declarations and metadata. It does "
                "not execute agents, models, tools, MCP servers, or network operations."
            ],
        }
        if "summary" in stages:
            write_json(staging / CI_SUMMARY_FILE, summary)
            artifacts.append(CI_SUMMARY_FILE)
            summary["artifacts"] = sorted(artifacts)
            write_json(staging / CI_SUMMARY_FILE, summary)
        _publish_directory(staging, output_dir)

    return ("" if args.quiet else _render_summary(summary, args.format), code)
