#!/usr/bin/env python3
"""Verify deterministic staged-CI release evidence from a clean local checkout.

The helper deliberately creates its configuration only in temporary directories.  It
never adds a repository-root ``trustweave.toml`` or writes release artifacts into the
working tree.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

from trustweave.cli import main as cli_main

ROOT = Path(__file__).resolve().parents[1]
FIXED_GENERATED_AT = "2026-08-19T00:00:00+00:00"
REQUIRED_INPUTS = (
    Path("examples/support-agent.manifest.json"),
    Path("policies/default-policy.json"),
    Path("scenarios/default-scenarios.json"),
    Path("examples/chains/safe-sanitized-external.chain.json"),
)
STAGES = (
    "scan",
    "scenarios",
    "policy_review",
    "chain_review",
    "sarif",
    "attestation",
    "report",
    "summary",
)
EXPECTED_ARTIFACTS = frozenset(
    {
        "agent-security-bundle.json",
        "attestation.json",
        "chain-review.json",
        "chain-review.md",
        "ci-summary.json",
        "policy-review.json",
        "policy-review.md",
        "report.md",
        "reports/trustweave.sarif",
        "security-test-results.json",
    }
)


def _git_status() -> str:
    """Return the repository status without modifying the checkout."""

    completed = subprocess.run(
        ["git", "status", "--porcelain"],
        check=True,
        cwd=ROOT,
        capture_output=True,
        encoding="utf-8",
    )
    return completed.stdout


def _git_head() -> str:
    """Return the exact checked-out source revision."""

    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=True,
        cwd=ROOT,
        capture_output=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _relative_input(run_directory: Path, input_path: Path) -> str:
    """Render one tracked source input relative to a temporary config directory."""

    return Path(os.path.relpath(ROOT / input_path, run_directory)).as_posix()


def _write_temporary_config(run_directory: Path) -> Path:
    """Write one explicit local-only config with relative artifact destinations."""

    manifest, policy, scenarios, chain_manifest = (
        _relative_input(run_directory, path) for path in REQUIRED_INPUTS
    )
    stages = ", ".join(f'"{stage}"' for stage in STAGES)
    path = run_directory / "trustweave.toml"
    path.write_text(
        "[tool.trustweave]\n"
        f'manifest = "{manifest}"\n'
        f'policy = "{policy}"\n'
        f'scenarios = "{scenarios}"\n'
        f'chain_manifest = "{chain_manifest}"\n'
        'output_dir = "artifacts"\n'
        'sarif_output = "reports/trustweave.sarif"\n'
        f"enabled_stages = [{stages}]\n"
        'failure_threshold = "none"\n'
        "reproducible = true\n",
        encoding="utf-8",
    )
    return path


def _run_staged_ci(run_directory: Path, *, generated_at: str, source_revision: str) -> Path:
    """Run the complete documented local stage selection into one temporary tree."""

    config_path = _write_temporary_config(run_directory)
    exit_code = cli_main(
        [
            "--generated-at",
            generated_at,
            "ci",
            "--config",
            str(config_path),
            "--source-revision",
            source_revision,
            "--quiet",
        ]
    )
    if exit_code != 0:
        raise SystemExit(f"staged CI exited {exit_code} for {run_directory}")
    artifact_directory = run_directory / "artifacts"
    if not artifact_directory.is_dir():
        raise SystemExit(f"staged CI did not create artifact directory: {artifact_directory}")
    return artifact_directory


def _artifact_files(directory: Path) -> dict[str, Path]:
    """Return all regular artifact files indexed by portable relative path."""

    return {
        path.relative_to(directory).as_posix(): path
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def _compare_artifacts(first: Path, second: Path) -> None:
    """Require identical artifact path sets and byte content for both runs."""

    first_files = _artifact_files(first)
    second_files = _artifact_files(second)
    if set(first_files) != EXPECTED_ARTIFACTS:
        raise SystemExit(
            "first staged-CI artifact set differs from the documented release set: "
            f"{sorted(first_files)}"
        )
    if set(second_files) != EXPECTED_ARTIFACTS:
        raise SystemExit(
            "second staged-CI artifact set differs from the documented release set: "
            f"{sorted(second_files)}"
        )
    differing = [
        relative_path
        for relative_path in sorted(first_files)
        if first_files[relative_path].read_bytes() != second_files[relative_path].read_bytes()
    ]
    if differing:
        raise SystemExit("staged-CI artifact bytes differ: " + ", ".join(differing))


def _assert_no_path_leakage(directory: Path) -> None:
    """Reject temporary, checkout-specific, and platform-specific output path leakage."""

    forbidden = (
        ".trustweave-ci-",
        ".trustweave-release-repro-",
        "/tmp/",
        str(ROOT.resolve()),
        str(directory.resolve()),
    )
    leaks: list[str] = []
    for relative_path, path in _artifact_files(directory).items():
        text = path.read_bytes().decode("utf-8", errors="replace")
        for marker in forbidden:
            if marker in text:
                leaks.append(f"{relative_path}: {marker}")
    if leaks:
        raise SystemExit(
            "generated artifacts contain machine-specific path leakage: " + "; ".join(leaks)
        )


def _verify_supplied_attestation(directory: Path) -> None:
    """Verify v1alpha3 attestation bindings against actual supplied output files."""

    exit_code = cli_main(
        [
            "verify",
            "--attestation",
            str(directory / "attestation.json"),
            "--bundle",
            str(directory / "agent-security-bundle.json"),
            "--test-results",
            str(directory / "security-test-results.json"),
        ]
    )
    if exit_code != 0:
        raise SystemExit("supplied-file attestation verification failed")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run two temporary configured local CI executions and verify deterministic release "
            "evidence without modifying the checkout."
        )
    )
    parser.add_argument(
        "--source-revision",
        required=True,
        help="Exact checked-out Git SHA recorded in both attestations.",
    )
    parser.add_argument(
        "--generated-at",
        default=FIXED_GENERATED_AT,
        help=f"Fixed ISO-8601 timestamp for both runs (default: {FIXED_GENERATED_AT}).",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Test-only escape hatch; otherwise require a clean repository working tree.",
    )
    return parser.parse_args()


def main() -> int:
    """Execute the documented clean-checkout reproducibility verification."""

    args = _parse_args()
    for input_path in REQUIRED_INPUTS:
        if not (ROOT / input_path).is_file():
            raise SystemExit(f"required tracked input does not exist: {input_path}")
    initial_status = _git_status()
    if initial_status and not args.allow_dirty:
        raise SystemExit("release reproducibility verification requires a clean working tree")
    checked_out_revision = _git_head()
    if args.source_revision != checked_out_revision:
        raise SystemExit(
            f"--source-revision must equal the exact checked-out Git SHA: {checked_out_revision}"
        )

    with (
        tempfile.TemporaryDirectory(prefix=".trustweave-release-repro-", dir=ROOT) as first_run,
        tempfile.TemporaryDirectory(prefix=".trustweave-release-repro-", dir=ROOT) as second_run,
    ):
        first_artifacts = _run_staged_ci(
            Path(first_run), generated_at=args.generated_at, source_revision=args.source_revision
        )
        second_artifacts = _run_staged_ci(
            Path(second_run), generated_at=args.generated_at, source_revision=args.source_revision
        )
        _compare_artifacts(first_artifacts, second_artifacts)
        _assert_no_path_leakage(first_artifacts)
        _assert_no_path_leakage(second_artifacts)
        _verify_supplied_attestation(first_artifacts)
        _verify_supplied_attestation(second_artifacts)

    if _git_status() != initial_status:
        raise SystemExit("release reproducibility verification changed the repository working tree")
    print(
        "Release staged-CI reproducibility passed: two 10-artifact trees are byte-identical, "
        "path-clean, and supplied-file attestation verification passed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
