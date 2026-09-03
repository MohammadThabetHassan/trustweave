"""Configured local CI evidence coordination command."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path, PureWindowsPath
from typing import Any

from trustweave.bundles import validate_bundle
from trustweave.chain import render_chain_review, review_declared_chains
from trustweave.commands._shared import (
    ATTESTATION_FILE,
    BUNDLE_FILE,
    CHAIN_REVIEW_FILE,
    CHAIN_REVIEW_REPORT_FILE,
    DIFF_FILE,
    DIFF_REPORT_FILE,
    EXIT_REVIEW,
    MCP_PROFILE_REVIEW_FILE,
    MCP_PROFILE_REVIEW_REPORT_FILE,
    POLICY_REVIEW_FILE,
    POLICY_REVIEW_REPORT_FILE,
    REPORT_FILE,
    RISK_REVIEW_FILE,
    RISK_REVIEW_REPORT_FILE,
    TEST_RESULTS_FILE,
    TRACE_REVIEW_FILE,
    TRACE_REVIEW_REPORT_FILE,
    configured_paths,
)
from trustweave.config import (
    PATH_FIELDS,
    VALID_WORKFLOW_STAGES,
    find_project_config,
    load_project_config,
)
from trustweave.diff import diff_bundles
from trustweave.engine import build_bundle
from trustweave.evidence import build_attestation
from trustweave.io import canonical_json, load_document, read_json, write_json, write_text
from trustweave.mcp_profile import parse_mcp_profile, review_mcp_profile
from trustweave.models import InputOutputError, ValidationError, parse_manifest, parse_policy
from trustweave.policy_review import review_policy
from trustweave.report import (
    render_diff_report,
    render_mcp_profile_review_report,
    render_policy_review_report,
    render_report,
    render_risk_review_report,
    render_trace_review_report,
)
from trustweave.risk import (
    ACTIVE_RISK_STATES,
    VALID_SEVERITIES,
    review_risks,
    should_fail,
    validate_decision_document,
)
from trustweave.sarif import build_sarif
from trustweave.scenarios import parse_scenarios, run_scenarios
from trustweave.trace_review import parse_trace, review_trace

CI_SUMMARY_FILE = "ci-summary.json"
CI_SUMMARY_SCHEMA_VERSION = "trustweave.dev/ci-summary/v1alpha1"
DEFAULT_STAGES = ("scan", "scenarios", "policy_review", "attestation", "report", "summary")
CI_SUPPORTED_STAGES = VALID_WORKFLOW_STAGES
SEVERITY_RANK = {severity: index for index, severity in enumerate(VALID_SEVERITIES)}
STAGE_DEPENDENCIES = {
    "policy_coverage": frozenset({"policy_review"}),
    "attestation": frozenset({"scan", "scenarios"}),
    "report": frozenset({"scan", "scenarios", "attestation"}),
}
REVIEW_STAGES = frozenset(
    {"policy_review", "diff", "trace_review", "mcp_profile_review", "chain_review"}
)


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
        choices=[*VALID_SEVERITIES, "review", "none"],
        help="Return status 1 at the selected severity, or for any finding with review.",
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


def _validate_stage_dependencies(stages: Sequence[str]) -> None:
    """Reject impossible declared stage combinations before staging local artifacts."""

    selected = set(stages)
    for stage, dependencies in STAGE_DEPENDENCIES.items():
        if stage in selected and not dependencies.issubset(selected):
            missing = ", ".join(sorted(dependencies - selected))
            raise ValidationError(f"{stage} stage requires selected stages: {missing}")
    if "risk" in selected and not (selected & REVIEW_STAGES):
        raise ValidationError("risk stage requires at least one selected local review stage")
    if "sarif" in selected and not ("risk" in selected or selected & REVIEW_STAGES):
        raise ValidationError(
            "sarif stage requires risk or at least one selected local review stage"
        )


def _required_paths(stages: Sequence[str]) -> set[str]:
    """Return declared local inputs required by selected stages before publication starts."""

    required: set[str] = set()
    if "scan" in stages:
        required.update({"manifest", "policy"})
    if "scenarios" in stages:
        required.update({"policy", "scenarios"})
    if "policy_review" in stages:
        required.add("policy")
    if "diff" in stages:
        required.update({"baseline_bundle", "candidate_bundle"})
    if "trace_review" in stages:
        required.update({"manifest", "policy", "trace"})
    if "mcp_profile_review" in stages:
        required.update({"manifest", "mcp_profile"})
    if "chain_review" in stages:
        required.add("chain_manifest")
    return required


def _safe_sarif_path(config: Mapping[str, object]) -> Path:
    """Validate one portable relative SARIF path without touching the filesystem."""

    configured = config.get("sarif_output", "trustweave.sarif")
    if not isinstance(configured, str):
        raise ValidationError("tool.trustweave.sarif_output must be a local path string")
    path = Path(configured)
    windows_path = PureWindowsPath(configured)
    if (
        path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or windows_path.root
        or ".." in path.parts
        or ".." in windows_path.parts
        or path == Path(".")
    ):
        raise ValidationError(
            "tool.trustweave.sarif_output must remain within the CI artifact directory"
        )
    if "\\" in configured:
        raise ValidationError(
            "tool.trustweave.sarif_output must use portable relative path separators"
        )
    return path


def _staged_sarif_path(config: Mapping[str, object], staging: Path) -> Path:
    """Return a configured SARIF path that cannot escape the staged artifact directory."""

    return staging / _safe_sarif_path(config)


def _validate_output_path(output: Path) -> None:
    """Reject symbolic-link output boundaries without creating any path on disk."""

    for candidate in (output, *output.parents):
        if candidate.is_symlink():
            raise InputOutputError(f"CI output path must not traverse a symbolic link: {candidate}")


def _prepare_output_parent(output: Path) -> None:
    """Create a local output parent without accepting symbolic-link directory boundaries."""

    _validate_output_path(output)
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise InputOutputError(
            f"Could not create CI output parent {output.parent}: {error.strerror or error}"
        ) from error


def _known_artifact_names() -> frozenset[str]:
    """Every filename TrustWeave itself publishes into an output directory."""

    from trustweave.commands import _shared

    modules = (_shared, sys.modules[__name__])
    return frozenset(
        value
        for module in modules
        for name, value in vars(module).items()
        if name.endswith("_FILE") and isinstance(value, str)
    )


def _refuse_to_replace_unrelated_content(staging: Path, output: Path) -> None:
    """Refuse to publish over a directory holding anything TrustWeave did not write.

    Publishing moves the existing directory aside and then deletes it. A one-word config
    typo naming a source directory would therefore destroy real work with no prompt and
    no warning, so an unrecognised entry stops the publish instead.
    """

    if not output.is_dir():
        return
    # Whatever this run just staged is by definition ours, including a SARIF file the
    # configuration renamed or nested. Deriving the list from _FILE constants alone made
    # TrustWeave refuse to overwrite its own output whenever sarif_output was not the
    # default, so a documented configuration was green once and exit 3 for ever after.
    known = _known_artifact_names() | {entry.name for entry in staging.iterdir()}
    unrelated = sorted(
        entry.name
        for entry in output.iterdir()
        if entry.name not in known and not entry.name.startswith(".")
    )
    if unrelated:
        listed = ", ".join(unrelated[:5])
        more = f" and {len(unrelated) - 5} more" if len(unrelated) > 5 else ""
        raise InputOutputError(
            f"Refusing to publish CI artifacts into {output}: it holds "
            f"{len(unrelated)} entries TrustWeave did not write ({listed}{more}). "
            "Point output_dir at a dedicated directory, or empty this one first."
        )


def _publish_directory(staging: Path, output: Path) -> None:
    """Atomically replace one artifact directory, restoring the prior directory on failure."""

    if output.is_symlink():
        raise InputOutputError(f"CI output path must not be a symbolic link: {output}")
    if output.exists() and not output.is_dir():
        raise InputOutputError(f"CI output path must be a directory: {output}")
    _refuse_to_replace_unrelated_content(staging, output)
    _prepare_output_parent(output)
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


def _review_findings(review: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Return canonical review findings or diff signals from one selected local artifact."""

    raw = review.get("findings", review.get("signals", []))
    if not isinstance(raw, list):
        return []
    return [finding for finding in raw if isinstance(finding, Mapping)]


def _severity_counts(findings: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    """Return a complete deterministic severity-count envelope for summary contracts."""

    counts = {severity: 0 for severity in (*VALID_SEVERITIES, "review")}
    for finding in findings:
        severity = finding.get("severity")
        if isinstance(severity, str) and severity in counts:
            counts[severity] += 1
    return counts


def _fail_on_findings(
    reviews: Mapping[str, Any] | Sequence[Mapping[str, Any] | None] | None,
    threshold: str,
    exit_on_review: bool,
) -> bool:
    """Evaluate every selected local review finding without implying remediation or enforcement."""

    selected = (reviews,) if isinstance(reviews, Mapping) else reviews
    if selected is None:
        return False
    findings = [
        finding for review in selected if review is not None for finding in _review_findings(review)
    ]
    if not findings:
        return False
    if exit_on_review:
        return True
    if threshold == "none":
        return False
    if threshold == "review":
        return True
    minimum = SEVERITY_RANK[threshold]
    return any(
        isinstance(finding.get("severity"), str)
        and (severity := finding["severity"]) in SEVERITY_RANK
        and SEVERITY_RANK[severity] <= minimum
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
    _validate_stage_dependencies(stages)
    reproducible = config.get("reproducible", False)
    if not isinstance(reproducible, bool):
        raise ValidationError("tool.trustweave.reproducible must be a boolean")
    if reproducible and getattr(args, "generated_at_source", "clock") == "clock":
        raise ValidationError(
            "reproducible CI requires --generated-at or SOURCE_DATE_EPOCH; wall-clock provenance "
            "is not deterministic"
        )
    required = _required_paths(stages)
    validation_inputs = (
        {name for name in config if name in PATH_FIELDS - {"output_dir", "sarif_output"}}
        if "validate" in stages
        else set()
    )
    path_values: dict[str, Path | None] = {
        **{name: None for name in sorted(required | validation_inputs)},
        "output_dir": args.output_dir,
    }
    if "risk" in stages:
        for name in ("risk_baseline", "suppressions"):
            if name in config:
                path_values[name] = None
    paths = configured_paths(config_path, path_values)
    output_dir = paths["output_dir"]
    if "validate" in stages:
        validated_documents = {
            name: load_document(paths[name]) for name in sorted(required | validation_inputs)
        }
        if "manifest" in validated_documents:
            parse_manifest(validated_documents["manifest"])
        if "policy" in validated_documents:
            parse_policy(validated_documents["policy"])
        if "scenarios" in validated_documents:
            parse_scenarios(validated_documents["scenarios"])
        if "mcp_profile" in validated_documents:
            parse_mcp_profile(validated_documents["mcp_profile"])
        if "chain_manifest" in validated_documents:
            review_declared_chains(validated_documents["chain_manifest"], generated_at)
        if "trace" in validated_documents:
            parse_trace(validated_documents["trace"])
        if "risk_baseline" in validated_documents:
            validate_decision_document(validated_documents["risk_baseline"], "baseline")
        if "suppressions" in validated_documents:
            validate_decision_document(validated_documents["suppressions"], "suppressions")
        for bundle_name in ("baseline_bundle", "candidate_bundle"):
            if bundle_name in validated_documents:
                validate_bundle(validated_documents[bundle_name], bundle_name)
        _validate_output_path(output_dir)
        _safe_sarif_path(config)
    configured_threshold = config.get("failure_threshold", "none")
    if not isinstance(configured_threshold, str):
        raise ValidationError("tool.trustweave.failure_threshold must be a severity string")
    threshold = args.fail_on or configured_threshold
    _prepare_output_parent(output_dir)

    with tempfile.TemporaryDirectory(prefix=".trustweave-ci-", dir=output_dir.parent) as temporary:
        staging = Path(temporary) / "artifacts"
        staging.mkdir()
        manifest = None
        policy = None
        bundle_path: Path | None = None
        test_path: Path | None = None
        attestation_path: Path | None = None
        policy_review: Mapping[str, Any] | None = None
        diff_review: Mapping[str, Any] | None = None
        trace_review: Mapping[str, Any] | None = None
        mcp_profile_review: Mapping[str, Any] | None = None
        chain_review: Mapping[str, Any] | None = None
        risk_review: Mapping[str, Any] | None = None
        raw_reviews: dict[str, tuple[str, Mapping[str, Any]]] = {}
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
            raw_reviews["policy"] = (POLICY_REVIEW_FILE, policy_review)
            artifacts.extend((POLICY_REVIEW_FILE, POLICY_REVIEW_REPORT_FILE))
        if "diff" in stages:
            diff_review = diff_bundles(
                read_json(paths["baseline_bundle"]),
                read_json(paths["candidate_bundle"]),
                generated_at,
            )
            write_json(staging / DIFF_FILE, diff_review)
            write_text(staging / DIFF_REPORT_FILE, render_diff_report(diff_review))
            raw_reviews["diff"] = (DIFF_FILE, diff_review)
            artifacts.extend((DIFF_FILE, DIFF_REPORT_FILE))
        if "trace_review" in stages:
            manifest = manifest or parse_manifest(read_json(paths["manifest"]))
            policy = policy or parse_policy(read_json(paths["policy"]))
            trace_review = review_trace(manifest, policy, read_json(paths["trace"]), generated_at)
            write_json(staging / TRACE_REVIEW_FILE, trace_review)
            write_text(staging / TRACE_REVIEW_REPORT_FILE, render_trace_review_report(trace_review))
            raw_reviews["trace"] = (TRACE_REVIEW_FILE, trace_review)
            artifacts.extend((TRACE_REVIEW_FILE, TRACE_REVIEW_REPORT_FILE))
        if "mcp_profile_review" in stages:
            manifest = manifest or parse_manifest(load_document(paths["manifest"]))
            profile = parse_mcp_profile(load_document(paths["mcp_profile"]))
            mcp_profile_review = review_mcp_profile(profile, manifest, generated_at)
            write_json(staging / MCP_PROFILE_REVIEW_FILE, mcp_profile_review)
            write_text(
                staging / MCP_PROFILE_REVIEW_REPORT_FILE,
                render_mcp_profile_review_report(mcp_profile_review),
            )
            raw_reviews["mcp"] = (MCP_PROFILE_REVIEW_FILE, mcp_profile_review)
            artifacts.extend((MCP_PROFILE_REVIEW_FILE, MCP_PROFILE_REVIEW_REPORT_FILE))
        if "chain_review" in stages:
            chain_review = review_declared_chains(read_json(paths["chain_manifest"]), generated_at)
            write_json(staging / CHAIN_REVIEW_FILE, chain_review)
            write_text(staging / CHAIN_REVIEW_REPORT_FILE, render_chain_review(chain_review))
            raw_reviews["chain"] = (CHAIN_REVIEW_FILE, chain_review)
            artifacts.extend((CHAIN_REVIEW_FILE, CHAIN_REVIEW_REPORT_FILE))
        if "risk" in stages:
            risk_review = review_risks(
                [review for _, review in raw_reviews.values()],
                baseline_document=(
                    load_document(paths["risk_baseline"]) if "risk_baseline" in paths else None
                ),
                suppressions_document=(
                    load_document(paths["suppressions"]) if "suppressions" in paths else None
                ),
                reviewed_at=generated_at,
                artifact_paths=[path for path, _ in raw_reviews.values()],
            )
            write_json(staging / RISK_REVIEW_FILE, risk_review)
            write_text(staging / RISK_REVIEW_REPORT_FILE, render_risk_review_report(risk_review))
            artifacts.extend((RISK_REVIEW_FILE, RISK_REVIEW_REPORT_FILE))
        if "sarif" in stages:
            sarif_reviews = (
                {"risk": (RISK_REVIEW_FILE, risk_review)}
                if risk_review is not None
                else raw_reviews
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
                    bundle_name=BUNDLE_FILE,
                    test_results_name=TEST_RESULTS_FILE,
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
        risk_has_active_finding = risk_review is not None and any(
            isinstance(finding, Mapping) and finding.get("risk_state") in ACTIVE_RISK_STATES
            for finding in risk_review.get("findings", [])
        )
        review_failed = (
            (
                risk_has_active_finding
                if args.exit_on_review
                else should_fail(risk_review, threshold)
            )
            if risk_review is not None
            else _fail_on_findings(
                [review for _, review in raw_reviews.values()], threshold, args.exit_on_review
            )
        )
        code = EXIT_REVIEW if test_failed or review_failed else 0
        raw_findings = [
            finding for _, review in raw_reviews.values() for finding in _review_findings(review)
        ]
        risk_findings = _review_findings(risk_review) if risk_review is not None else raw_findings
        active_findings = (
            [
                finding
                for finding in risk_findings
                if finding.get("risk_state") in ACTIVE_RISK_STATES
            ]
            if risk_review is not None
            else raw_findings
        )
        risk_summary = risk_review.get("summary", {}) if risk_review is not None else {}
        incomplete_analyses = sorted(
            {
                "Declared chain analysis reached a configured traversal budget."
                for finding in raw_findings
                if finding.get("id") == "TW-CHAIN-004"
            }
        )
        summary: dict[str, Any] = {
            "schema_version": CI_SUMMARY_SCHEMA_VERSION,
            "generated_at": generated_at,
            "provenance": {
                "generated_at_source": getattr(args, "generated_at_source", "clock"),
                "source_revision": args.source_revision,
            },
            "status": "review_required" if code == EXIT_REVIEW else "clear",
            "stages": list(stages),
            "artifacts": sorted(artifacts),
            "finding_counts": _severity_counts(risk_findings),
            "active_severity_counts": _severity_counts(active_findings),
            "review": {
                "selected_kinds": sorted([*raw_reviews, *(["risk"] if risk_review else [])]),
                "uses_risk_lifecycle": risk_review is not None,
            },
            "incomplete_analyses": incomplete_analyses,
            "applied_decisions": {
                "baselined": risk_summary.get("baselined", 0),
                "suppressed": risk_summary.get("suppressed", 0),
                "expired_baseline": risk_summary.get("expired_baseline", 0),
                "expired_suppression": risk_summary.get("expired_suppression", 0),
            },
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
