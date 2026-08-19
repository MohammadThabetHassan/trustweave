#!/usr/bin/env python3
"""Generate and verify TrustWeave's synthetic deterministic golden evidence corpus.

The default mode is check-only: it writes only beneath a temporary directory, compares the
regenerated evidence with the reviewed corpus manifest, and removes temporary output before
returning. Updating digests requires a separate explicit maintainer confirmation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from trustweave.cli import main as cli_main

ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "docs" / "golden-evidence" / "corpus-v1.json"
FIXED_GENERATED_AT = "2026-08-19T00:00:00+00:00"
SOURCE_REVISION = "golden-evidence-v1"
UPDATE_CONFIRMATION = "I_HAVE_REVIEWED_GOLDEN_EVIDENCE"
FORBIDDEN_OUTPUT_MARKERS = (
    ".trustweave-golden-",
    ".trustweave-release-repro-",
    "/tmp/",
    "\\\\tmp\\\\",
    "token=",
    "synthetic@example.invalid",
)


@dataclass(frozen=True)
class CommandSpec:
    """One local-only golden-corpus command and its expected exit status."""

    label: str
    argv_template: tuple[str, ...]
    expected_exit: int


@dataclass(frozen=True)
class CaseSpec:
    """One bounded synthetic case used to generate deterministic review evidence."""

    identifier: str
    purpose: str
    commands: tuple[CommandSpec, ...]
    require_no_artifacts: bool = False


def _command(label: str, expected_exit: int, *argv_template: str) -> CommandSpec:
    """Create one readable immutable command specification."""

    return CommandSpec(label=label, argv_template=argv_template, expected_exit=expected_exit)


CASE_SPECS = (
    CaseSpec(
        identifier="baseline-ci",
        purpose=(
            "Complete clear synthetic CI evidence bundle, including local attestation, report, "
            "policy review, chain review, SARIF, and summary."
        ),
        commands=(
            _command(
                "complete_staged_ci",
                0,
                "--generated-at",
                FIXED_GENERATED_AT,
                "ci",
                "--config",
                "{temporary_config}",
                "--source-revision",
                SOURCE_REVISION,
                "--quiet",
            ),
        ),
    ),
    CaseSpec(
        identifier="framework-imports",
        purpose="Checked-in LangGraph, OpenAI Agents, and CrewAI declaration snapshots only.",
        commands=(
            _command(
                "langgraph",
                0,
                "--generated-at",
                FIXED_GENERATED_AT,
                "framework-import",
                "--framework",
                "langgraph",
                "--input",
                "{root}/examples/frameworks/langgraph.json",
                "--output-dir",
                "{output_dir}/langgraph",
            ),
            _command(
                "openai_agents",
                0,
                "--generated-at",
                FIXED_GENERATED_AT,
                "framework-import",
                "--framework",
                "openai-agents",
                "--input",
                "{root}/examples/frameworks/openai-agents-descriptor.json",
                "--output-dir",
                "{output_dir}/openai-agents",
            ),
            _command(
                "crewai",
                0,
                "--generated-at",
                FIXED_GENERATED_AT,
                "framework-import",
                "--framework",
                "crewai",
                "--input",
                "{root}/examples/frameworks/crewai-crew.json",
                "--output-dir",
                "{output_dir}/crewai",
            ),
        ),
    ),
    CaseSpec(
        identifier="mcp-profile-review",
        purpose=(
            "Saved MCP tools/list metadata plus clear and review-required profiles; no network "
            "connection, authentication, discovery, or invocation."
        ),
        commands=(
            _command(
                "saved_tools_list",
                0,
                "--generated-at",
                FIXED_GENERATED_AT,
                "mcp-import",
                "--tool-list",
                "{root}/examples/mcp-tools/support-tools-list.json",
                "--output-dir",
                "{output_dir}/inventory",
            ),
            _command(
                "clear_profile",
                0,
                "--generated-at",
                FIXED_GENERATED_AT,
                "mcp-profile-check",
                "--manifest",
                "{root}/examples/support-agent.manifest.json",
                "--profile",
                "{root}/examples/mcp-profiles/clear-support-profile.json",
                "--output-dir",
                "{output_dir}/clear",
                "--exit-on-review",
            ),
            _command(
                "review_required_profile",
                1,
                "--generated-at",
                FIXED_GENERATED_AT,
                "mcp-profile-check",
                "--manifest",
                "{root}/examples/support-agent.manifest.json",
                "--profile",
                "{root}/examples/mcp-profiles/review-required-support-profile.json",
                "--output-dir",
                "{output_dir}/review-required",
                "--exit-on-review",
            ),
        ),
    ),
    CaseSpec(
        identifier="trace-risk-lifecycle",
        purpose=(
            "Minimized clear and review-required trace metadata with a local risk lifecycle "
            "review that excludes message contents and tool arguments from rendered output."
        ),
        commands=(
            _command(
                "clear_trace",
                0,
                "--generated-at",
                FIXED_GENERATED_AT,
                "trace-review",
                "--manifest",
                "{root}/examples/support-agent.manifest.json",
                "--policy",
                "{root}/policies/default-policy.json",
                "--trace",
                "{root}/examples/traces/clear-support-trace.json",
                "--output-dir",
                "{output_dir}/clear",
                "--exit-on-review",
            ),
            _command(
                "review_required_trace",
                1,
                "--generated-at",
                FIXED_GENERATED_AT,
                "trace-review",
                "--manifest",
                "{root}/examples/support-agent.manifest.json",
                "--policy",
                "{root}/policies/default-policy.json",
                "--trace",
                "{root}/examples/traces/review-required-support-trace.json",
                "--output-dir",
                "{output_dir}/review-required",
                "--exit-on-review",
            ),
            _command(
                "risk_lifecycle",
                0,
                "--generated-at",
                FIXED_GENERATED_AT,
                "risk-check",
                "--input",
                "{output_dir}/review-required/trace-review.json",
                "--baseline",
                "{root}/docs/golden-evidence/golden-trace-risk/empty-baseline-v1alpha2.json",
                "--suppressions",
                "{root}/docs/golden-evidence/golden-trace-risk/empty-suppressions-v1alpha2.json",
                "--output",
                "{output_dir}/risk-review.json",
                "--markdown-output",
                "{output_dir}/risk-review.md",
                "--fail-on",
                "none",
            ),
        ),
    ),
    CaseSpec(
        identifier="change-review-sarif",
        purpose=(
            "Synthetic declared policy, bundle-diff, and SARIF review artifacts for a local "
            "capability growth; no live target or external code-scanning upload."
        ),
        commands=(
            _command(
                "base_bundle",
                0,
                "--generated-at",
                FIXED_GENERATED_AT,
                "scan",
                "--manifest",
                "{root}/examples/support-agent.manifest.json",
                "--policy",
                "{root}/policies/default-policy.json",
                "--output-dir",
                "{output_dir}/base",
            ),
            _command(
                "capability_growth_bundle",
                0,
                "--generated-at",
                FIXED_GENERATED_AT,
                "scan",
                "--manifest",
                "{root}/examples/support-agent.capability-growth.manifest.json",
                "--policy",
                "{root}/policies/default-policy.json",
                "--output-dir",
                "{output_dir}/growth",
            ),
            _command(
                "capability_diff",
                0,
                "--generated-at",
                FIXED_GENERATED_AT,
                "diff",
                "--base",
                "{output_dir}/base/agent-security-bundle.json",
                "--head",
                "{output_dir}/growth/agent-security-bundle.json",
                "--output-dir",
                "{output_dir}/diff",
            ),
            _command(
                "approval_control_review",
                1,
                "--generated-at",
                FIXED_GENERATED_AT,
                "policy-check",
                "--policy",
                "{root}/examples/policies/approval-control-missing.policy.json",
                "--output-dir",
                "{output_dir}/policy-review",
                "--exit-on-review",
            ),
            _command(
                "local_sarif",
                0,
                "--generated-at",
                FIXED_GENERATED_AT,
                "sarif",
                "--policy-review",
                "{output_dir}/policy-review/policy-review.json",
                "--diff",
                "{output_dir}/diff/bundle-diff.json",
                "--output",
                "{output_dir}/trustweave.sarif",
            ),
        ),
    ),
    CaseSpec(
        identifier="malformed-input",
        purpose="Unknown-field manifest rejection with no evidence-artifact publication.",
        commands=(
            _command(
                "unknown_field_rejected",
                2,
                "--generated-at",
                FIXED_GENERATED_AT,
                "scan",
                "--manifest",
                "{root}/docs/golden-evidence/golden-malformed/unknown-field.manifest.json",
                "--policy",
                "{root}/policies/default-policy.json",
                "--output-dir",
                "{output_dir}",
            ),
        ),
        require_no_artifacts=True,
    ),
)


def _render_argv(
    template: tuple[str, ...], *, case_directory: Path, output_dir: Path, config_path: Path
) -> list[str]:
    """Render one portable case-relative command specification without shell interpolation."""

    values = {
        "root": Path(os.path.relpath(ROOT, case_directory)).as_posix(),
        "output_dir": output_dir.relative_to(case_directory).as_posix(),
        "temporary_config": config_path.relative_to(case_directory).as_posix(),
    }
    return [part.format(**values) for part in template]


def _relative_input(run_directory: Path, input_path: Path) -> str:
    """Render one tracked input relative to a temporary configuration file."""

    return Path(os.path.relpath(ROOT / input_path, run_directory)).as_posix()


def _write_ci_config(case_directory: Path) -> Path:
    """Write the complete documented CI configuration only beneath the temporary case tree."""

    inputs = (
        Path("examples/support-agent.manifest.json"),
        Path("policies/default-policy.json"),
        Path("scenarios/default-scenarios.json"),
        Path("examples/chains/safe-sanitized-external.chain.json"),
    )
    manifest, policy, scenarios, chain_manifest = (
        _relative_input(case_directory, path) for path in inputs
    )
    path = case_directory / "trustweave.toml"
    path.write_text(
        "[tool.trustweave]\n"
        f'manifest = "{manifest}"\n'
        f'policy = "{policy}"\n'
        f'scenarios = "{scenarios}"\n'
        f'chain_manifest = "{chain_manifest}"\n'
        'output_dir = "artifacts"\n'
        'sarif_output = "reports/trustweave.sarif"\n'
        'enabled_stages = ["scan", "scenarios", "policy_review", "chain_review", '
        '"sarif", "attestation", "report", "summary"]\n'
        'failure_threshold = "none"\n'
        "reproducible = true\n",
        encoding="utf-8",
    )
    return path


def _artifact_files(directory: Path) -> dict[str, Path]:
    """Return regular artifact files indexed by portable relative path."""

    if not directory.is_dir():
        return {}
    return {
        path.relative_to(directory).as_posix(): path
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def _canonical_json_bytes(document: Any) -> bytes:
    """Render a JSON value with the stable encoding used for golden JSON digests."""

    return json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )


def _artifact_record(relative_path: str, path: Path) -> dict[str, str]:
    """Return one reviewed path/digest record for a generated local artifact."""

    if path.suffix in {".json", ".sarif"}:
        document = json.loads(path.read_text(encoding="utf-8"))
        digest = hashlib.sha256(_canonical_json_bytes(document)).hexdigest()
        return {
            "path": relative_path,
            "digest": digest,
            "digest_kind": "canonical-json-sha256",
        }
    return {
        "path": relative_path,
        "digest": hashlib.sha256(path.read_bytes()).hexdigest(),
        "digest_kind": "bytes-sha256",
    }


def _schema_validators() -> dict[str, Draft202012Validator]:
    """Load validators for every versioned artifact schema currently shipped by the repository."""

    validators: dict[str, Draft202012Validator] = {}
    for path in sorted((ROOT / "schemas").glob("*.schema.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        properties = document.get("properties")
        if not isinstance(properties, dict):
            continue
        schema_version = properties.get("schema_version")
        if not isinstance(schema_version, dict):
            continue
        version = schema_version.get("const")
        if isinstance(version, str):
            validators[version] = Draft202012Validator(document)
    return validators


def _assert_safe_output(
    relative_path: str, path: Path, validators: dict[str, Draft202012Validator]
) -> list[str]:
    """Validate path hygiene, privacy boundaries, JSON structure, and known artifact schemas."""

    failures: list[str] = []
    text = path.read_bytes().decode("utf-8", errors="replace")
    forbidden = FORBIDDEN_OUTPUT_MARKERS + (str(ROOT.resolve()),)
    for marker in forbidden:
        if marker in text:
            failures.append(f"{relative_path} contains forbidden output marker: {marker}")
    if path.suffix not in {".json", ".sarif"}:
        return failures
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        return failures + [f"{relative_path} is not valid JSON: {error}"]
    if not isinstance(document, dict):
        return failures + [f"{relative_path} must be a JSON object"]
    schema_version = document.get("schema_version")
    if isinstance(schema_version, str):
        validator = validators.get(schema_version)
        if validator is None:
            failures.append(f"{relative_path} has no shipped schema validator: {schema_version}")
        else:
            for error in sorted(
                validator.iter_errors(document), key=lambda issue: list(issue.path)
            ):
                location = ".".join(str(part) for part in error.path) or "<root>"
                failures.append(
                    f"{relative_path} violates {schema_version} at {location}: {error.message}"
                )
    if path.suffix == ".sarif" and document.get("version") != "2.1.0":
        failures.append(f"{relative_path} must declare SARIF version 2.1.0")
    return failures


def _case_manifest_record(case: CaseSpec, artifact_directory: Path) -> dict[str, Any]:
    """Build the checked-in manifest entry from a successful deterministic local case."""

    files = _artifact_files(artifact_directory)
    if case.require_no_artifacts:
        if files:
            raise ValueError(f"{case.identifier} unexpectedly published artifacts: {sorted(files)}")
        artifacts: list[dict[str, str]] = []
    else:
        if not files:
            raise ValueError(f"{case.identifier} did not publish any artifacts")
        artifacts = [_artifact_record(relative_path, path) for relative_path, path in files.items()]
    return {
        "id": case.identifier,
        "purpose": case.purpose,
        "commands": [
            {
                "label": command.label,
                "argv_template": list(command.argv_template),
                "expected_exit": command.expected_exit,
            }
            for command in case.commands
        ],
        "artifacts": artifacts,
    }


def _run_case(case: CaseSpec, run_root: Path) -> tuple[dict[str, Any], list[str]]:
    """Run one synthetic local case and return its generated manifest record and failures."""

    case_directory = run_root / case.identifier
    case_directory.mkdir(parents=True, exist_ok=False)
    output_directory = case_directory / "artifacts"
    config_path = (
        _write_ci_config(case_directory)
        if case.identifier == "baseline-ci"
        else case_directory / "unused.toml"
    )
    failures: list[str] = []
    original_directory = Path.cwd()
    try:
        os.chdir(case_directory)
        for command in case.commands:
            argv = _render_argv(
                command.argv_template,
                case_directory=case_directory,
                output_dir=output_directory,
                config_path=config_path,
            )
            exit_code = cli_main(argv)
            if exit_code != command.expected_exit:
                failures.append(
                    f"{case.identifier}/{command.label} exited {exit_code}, "
                    f"expected {command.expected_exit}"
                )
    finally:
        os.chdir(original_directory)
    try:
        record = _case_manifest_record(case, output_directory)
    except ValueError as error:
        failures.append(str(error))
        record = {
            "id": case.identifier,
            "purpose": case.purpose,
            "commands": [],
            "artifacts": [],
        }
    validators = _schema_validators()
    for relative_path, path in _artifact_files(output_directory).items():
        failures.extend(_assert_safe_output(relative_path, path, validators))
    return record, failures


def _build_manifest(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the versioned corpus manifest from reviewed synthetic case records."""

    return {
        "schema_version": "trustweave.dev/golden-evidence/v1alpha1",
        "fixed_generated_at": FIXED_GENERATED_AT,
        "source_revision": SOURCE_REVISION,
        "limits": {
            "local_only": True,
            "external_execution": "forbidden",
            "snapshot_updates": "explicit-maintainer-confirmation-required",
            "forbidden_output_markers": list(FORBIDDEN_OUTPUT_MARKERS),
        },
        "cases": records,
    }


def _load_manifest() -> dict[str, Any]:
    """Load the checked-in reviewed corpus manifest as one JSON object."""

    document = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("golden corpus manifest must be a JSON object")
    return document


def _validate_manifest_structure(document: dict[str, Any]) -> list[str]:
    """Reject incomplete, stale, or unreviewable golden-corpus manifest structure."""

    failures: list[str] = []
    if document.get("schema_version") != "trustweave.dev/golden-evidence/v1alpha1":
        failures.append("golden corpus manifest has an unexpected schema_version")
    if document.get("fixed_generated_at") != FIXED_GENERATED_AT:
        failures.append("golden corpus manifest fixed_generated_at differs from verifier contract")
    if document.get("source_revision") != SOURCE_REVISION:
        failures.append("golden corpus manifest source_revision differs from verifier contract")
    cases = document.get("cases")
    if not isinstance(cases, list):
        return failures + ["golden corpus manifest cases must be a list"]
    expected_identifiers = [case.identifier for case in CASE_SPECS]
    actual_identifiers = [case.get("id") for case in cases if isinstance(case, dict)]
    if actual_identifiers != expected_identifiers:
        failures.append(
            "golden corpus manifest cases differ from the verifier-owned synthetic case order"
        )
    for case in cases:
        if not isinstance(case, dict):
            failures.append("golden corpus manifest case entries must be objects")
            continue
        artifacts = case.get("artifacts")
        if not isinstance(artifacts, list):
            failures.append(f"golden corpus case {case.get('id')} artifacts must be a list")
            continue
        if case.get("id") != "malformed-input" and not artifacts:
            failures.append(f"golden corpus case {case.get('id')} must record artifacts")
        for artifact in artifacts:
            if not isinstance(artifact, dict) or set(artifact) != {"path", "digest", "digest_kind"}:
                failures.append(
                    f"golden corpus case {case.get('id')} has malformed artifact record"
                )
    return failures


def _compare_manifest(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    """Compare every reviewed command and digest field without allowing silent refreshes."""

    if expected == actual:
        return []
    failures: list[str] = []
    expected_cases = expected.get("cases")
    actual_cases = actual.get("cases")
    if not isinstance(expected_cases, list) or not isinstance(actual_cases, list):
        return ["golden corpus manifest comparison requires case lists"]
    for expected_case, actual_case in zip(expected_cases, actual_cases, strict=False):
        expected_id = expected_case.get("id") if isinstance(expected_case, dict) else "<invalid>"
        if expected_case != actual_case:
            failures.append(
                f"golden corpus drift detected for {expected_id}; run --update only "
                "after reviewing the input, command, output, and digest changes"
            )
    if len(expected_cases) != len(actual_cases):
        failures.append("golden corpus case count drift detected")
    return failures


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse check-only and explicit maintainer-update modes."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update",
        action="store_true",
        help="Write reviewed digest records after all synthetic commands complete successfully.",
    )
    parser.add_argument(
        "--confirm-update",
        help="Required exact maintainer confirmation for --update.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run checked-in synthetic cases without external execution or implicit snapshot updates."""

    args = _parse_args(argv)
    if args.update and args.confirm_update != UPDATE_CONFIRMATION:
        print("--update requires --confirm-update with the documented exact confirmation")
        return 2
    if not args.update and args.confirm_update is not None:
        print("--confirm-update is valid only with --update")
        return 2
    if not args.update and not CORPUS_PATH.is_file():
        print("Golden corpus manifest is missing; use the explicit reviewed update procedure")
        return 1

    with tempfile.TemporaryDirectory(prefix=".trustweave-golden-", dir=ROOT) as temporary_directory:
        records: list[dict[str, Any]] = []
        failures: list[str] = []
        for case in CASE_SPECS:
            record, case_failures = _run_case(case, Path(temporary_directory))
            records.append(record)
            failures.extend(case_failures)
        generated = _build_manifest(records)

    if failures:
        print("Golden evidence verification failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    if args.update:
        CORPUS_PATH.write_text(
            json.dumps(generated, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"Golden evidence corpus updated: {CORPUS_PATH.relative_to(ROOT)}")
        return 0

    expected = _load_manifest()
    structure_failures = _validate_manifest_structure(expected)
    comparison_failures = _compare_manifest(expected, generated)
    failures = structure_failures + comparison_failures
    if failures:
        print("Golden evidence verification failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(
        "Golden evidence verification passed: synthetic outputs match reviewed digests and limits."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
