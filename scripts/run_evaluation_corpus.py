#!/usr/bin/env python3
"""Run TrustWeave's safe synthetic evaluation corpus without network or runtime execution."""

from __future__ import annotations

import argparse
import contextlib
import copy
import io
import re
import tempfile
from pathlib import Path
from typing import Any, Final

from trustweave.cli import main
from trustweave.engine import build_bundle
from trustweave.io import load_document, read_json, write_json
from trustweave.models import parse_manifest, parse_policy

ROOT: Final[Path] = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS: Final[Path] = ROOT / "examples" / "evaluation-corpus" / "corpus.json"
FIXED_GENERATED_AT: Final[str] = "2026-08-20T00:00:00+00:00"
CORPUS_SCHEMA_VERSION: Final[str] = "trustweave.dev/evaluation-corpus/v1alpha1"
CORPUS_ID: Final[str] = "trustweave-synthetic-evaluation-corpus"
CORPUS_VERSION: Final[str] = "v1alpha1"
MINIMUM_CASES: Final[int] = 12
CASE_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"TW-EVAL-(?P<number>\d{3})")
VALID_OPERATIONS: Final[frozenset[str]] = frozenset(
    {"scan", "policy-check", "diff", "trace-review", "mcp-profile-check"}
)
ARTIFACT_BY_OPERATION: Final[dict[str, str]] = {
    "scan": "agent-security-bundle.json",
    "policy-check": "policy-review.json",
    "diff": "bundle-diff.json",
    "trace-review": "trace-review.json",
    "mcp-profile-check": "mcp-profile-review.json",
}


class CorpusError(ValueError):
    """Raised when a checked-in evaluation corpus contract is invalid."""


def _inside_root(value: str) -> Path:
    """Resolve one corpus reference and reject absolute or repository-escaping paths."""

    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise CorpusError(f"Corpus reference must be a relative in-repository path: {value}")
    resolved = (ROOT / candidate).resolve()
    if resolved != ROOT and ROOT not in resolved.parents:
        raise CorpusError(f"Corpus reference escapes the repository: {value}")
    if not resolved.is_file():
        raise CorpusError(f"Corpus reference does not name a checked-in file: {value}")
    return resolved


def _require_string(case: dict[str, Any], field: str) -> str:
    """Read a non-empty manifest string with a precise corpus-contract failure."""

    value = case.get(field)
    if not isinstance(value, str) or not value:
        raise CorpusError(f"Corpus case {case.get('id', '<unknown>')} requires non-empty {field}")
    return value


def _validate_corpus(corpus: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate the narrow, local-only corpus manifest before executing any case."""

    if corpus.get("schema_version") != CORPUS_SCHEMA_VERSION:
        raise CorpusError("Unsupported evaluation corpus schema_version")
    if corpus.get("corpus_id") != CORPUS_ID:
        raise CorpusError("Unsupported evaluation corpus_id")
    if corpus.get("corpus_version") != CORPUS_VERSION:
        raise CorpusError("Unsupported evaluation corpus_version")
    for field in ("description", "non_claim"):
        value = corpus.get(field)
        if not isinstance(value, str) or not value:
            raise CorpusError(f"Corpus requires a non-empty {field}")
    cases = corpus.get("cases")
    if not isinstance(cases, list) or len(cases) < MINIMUM_CASES:
        raise CorpusError(f"Corpus must contain at least {MINIMUM_CASES} cases")

    validated: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    clear_controls = 0
    for expected_number, raw_case in enumerate(cases, start=1):
        if not isinstance(raw_case, dict):
            raise CorpusError("Every corpus case must be an object")
        case = dict(raw_case)
        identifier = _require_string(case, "id")
        identifier_match = CASE_ID_PATTERN.fullmatch(identifier)
        if identifier_match is None or int(identifier_match["number"]) != expected_number:
            expected_id = f"TW-EVAL-{expected_number:03d}"
            raise CorpusError(
                f"Corpus case IDs must be ordered and contiguous; expected {expected_id}"
            )
        if identifier in identifiers:
            raise CorpusError(f"Duplicate corpus case id: {identifier}")
        identifiers.add(identifier)
        _require_string(case, "title")
        operation = _require_string(case, "operation")
        if operation not in VALID_OPERATIONS:
            raise CorpusError(f"Unsupported corpus operation for {identifier}: {operation}")
        expected_exit = case.get("expected_exit")
        if not isinstance(expected_exit, int) or expected_exit < 0 or expected_exit > 3:
            raise CorpusError(f"Corpus case {identifier} requires expected_exit from 0 through 3")
        for field in ("rationale", "non_claim"):
            _require_string(case, field)
        if "exit_on_review" in case and not isinstance(case["exit_on_review"], bool):
            raise CorpusError(f"Corpus case {identifier} exit_on_review must be boolean")
        for path_field in ("manifest", "policy", "trace", "profile"):
            if path_field in case:
                _inside_root(_require_string(case, path_field))
        if operation == "scan":
            _require_string(case, "manifest")
            _require_string(case, "policy")
        if operation == "policy-check":
            _require_string(case, "policy")
        if operation == "trace-review":
            for field in ("manifest", "policy", "trace"):
                _require_string(case, field)
        if operation == "mcp-profile-check":
            for field in ("manifest", "profile"):
                _require_string(case, field)
        if operation == "diff" and case.get("diff_variant") not in {
            "identical",
            "capability_growth",
            "approval_fail_open",
        }:
            raise CorpusError(f"Corpus case {identifier} uses an unsupported diff_variant")
        if operation != "scan" or expected_exit == 0:
            artifact = case.get("artifact")
            if artifact != ARTIFACT_BY_OPERATION[operation]:
                expected_artifact = ARTIFACT_BY_OPERATION[operation]
                raise CorpusError(
                    f"Corpus case {identifier} requires expected artifact {expected_artifact}"
                )
        assertions = case.get("assertions", [])
        if not isinstance(assertions, list):
            raise CorpusError(f"Corpus case {identifier} assertions must be a list")
        for raw_assertion in assertions:
            if not isinstance(raw_assertion, dict):
                raise CorpusError(f"Corpus case {identifier} has a non-object assertion")
            path = raw_assertion.get("path")
            if not isinstance(path, str) or not path or "equals" not in raw_assertion:
                raise CorpusError(f"Corpus case {identifier} assertion requires path and equals")
        signal_ids = case.get("expected_signal_ids")
        if signal_ids is not None and (
            not isinstance(signal_ids, list)
            or not all(isinstance(item, str) and item for item in signal_ids)
            or len(signal_ids) != len(set(signal_ids))
        ):
            message = "expected_signal_ids must be a unique non-empty string list"
            raise CorpusError(f"Corpus case {identifier} {message}")
        if any("http://" in value or "https://" in value for value in _string_values(case)):
            raise CorpusError(f"Corpus case {identifier} must not contain an external URL")
        if case.get("expected_exit") == 0 and any(
            assertion.get("path") == "summary.status" and assertion.get("equals") == "clear"
            for assertion in assertions
            if isinstance(assertion, dict)
        ):
            clear_controls += 1
        validated.append(case)
    if clear_controls < 3:
        raise CorpusError("Corpus requires at least three explicit clear/no-finding controls")
    return validated


def _string_values(value: object) -> list[str]:
    """Collect manifest strings for narrow external-URL rejection."""

    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for nested in value for item in _string_values(nested)]
    if isinstance(value, dict):
        return [item for nested in value.values() for item in _string_values(nested)]
    return []


def _command(arguments: list[str]) -> tuple[int, str, str]:
    """Execute one established local CLI command and retain only its local text output."""

    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        exit_code = main(["--generated-at", FIXED_GENERATED_AT, *arguments])
    return exit_code, stdout.getvalue().strip(), stderr.getvalue().strip()


def _nested_value(document: object, dotted_path: str) -> object:
    """Return a JSON value using a dotted object path."""

    current = document
    for segment in dotted_path.split("."):
        if not isinstance(current, dict) or segment not in current:
            raise CorpusError(f"Artifact assertion path does not exist: {dotted_path}")
        current = current[segment]
    return current


def _run_diff(case: dict[str, Any], output_dir: Path) -> tuple[int, str, str]:
    """Build only synthetic local bundle pairs for one checked-in diff variant."""

    manifest_document = copy.deepcopy(
        load_document(ROOT / "examples" / "support-agent.manifest.json")
    )
    policy_document = copy.deepcopy(load_document(ROOT / "policies" / "default-policy.json"))
    if not isinstance(manifest_document, dict) or not isinstance(policy_document, dict):
        raise CorpusError("Checked-in synthetic diff inputs must be objects")
    head_manifest = copy.deepcopy(manifest_document)
    head_policy = copy.deepcopy(policy_document)
    variant = case["diff_variant"]
    if variant == "capability_growth":
        tools = head_manifest.get("tools")
        if not isinstance(tools, list):
            raise CorpusError("Synthetic diff manifest has no tools list")
        matching = [
            tool
            for tool in tools
            if isinstance(tool, dict) and tool.get("name") == "lookup_customer_record"
        ]
        if len(matching) != 1 or not isinstance(matching[0].get("capabilities"), list):
            raise CorpusError("Synthetic diff capability fixture is malformed")
        matching[0]["capabilities"].append("customer-record.export")
    elif variant == "approval_fail_open":
        approval_control = head_policy.get("approval_control")
        if not isinstance(approval_control, dict):
            raise CorpusError("Synthetic diff policy has no approval_control")
        approval_control["fail_closed"] = False

    base_bundle = build_bundle(
        parse_manifest(manifest_document),
        parse_policy(policy_document),
        generated_at=FIXED_GENERATED_AT,
    )
    head_bundle = build_bundle(
        parse_manifest(head_manifest), parse_policy(head_policy), generated_at=FIXED_GENERATED_AT
    )
    base_path = write_json(output_dir / "base-bundle.json", base_bundle)
    head_path = write_json(output_dir / "head-bundle.json", head_bundle)
    return _command(
        [
            "diff",
            "--base",
            str(base_path),
            "--head",
            str(head_path),
            "--output-dir",
            str(output_dir),
        ]
    )


def _run_case(case: dict[str, Any], output_dir: Path) -> tuple[int, str, str]:
    """Run one local-only corpus operation against a fresh case output directory."""

    operation = str(case["operation"])
    if operation == "diff":
        return _run_diff(case, output_dir)
    arguments: list[str] = [operation]
    if operation == "scan":
        arguments.extend(
            [
                "--manifest",
                str(_inside_root(case["manifest"])),
                "--policy",
                str(_inside_root(case["policy"])),
            ]
        )
    elif operation == "policy-check":
        arguments.extend(["--policy", str(_inside_root(case["policy"]))])
    elif operation == "trace-review":
        arguments.extend(
            [
                "--manifest",
                str(_inside_root(case["manifest"])),
                "--policy",
                str(_inside_root(case["policy"])),
                "--trace",
                str(_inside_root(case["trace"])),
            ]
        )
    elif operation == "mcp-profile-check":
        arguments.extend(
            [
                "--manifest",
                str(_inside_root(case["manifest"])),
                "--profile",
                str(_inside_root(case["profile"])),
            ]
        )
    arguments.extend(["--output-dir", str(output_dir)])
    if case.get("exit_on_review") is True:
        arguments.append("--exit-on-review")
    return _command(arguments)


def _assert_case(case: dict[str, Any], output_dir: Path, actual_exit: int) -> dict[str, object]:
    """Check the declared local exit code and semantic artifact assertions for one case."""

    expected_exit = int(case["expected_exit"])
    result: dict[str, object] = {
        "id": case["id"],
        "title": case["title"],
        "operation": case["operation"],
        "expected_exit": expected_exit,
        "actual_exit": actual_exit,
        "status": "passed",
        "rationale": case["rationale"],
        "non_claim": case["non_claim"],
        "assertions": [],
    }
    if actual_exit != expected_exit:
        result["status"] = "failed"
        result["reason"] = f"Expected exit {expected_exit}, received {actual_exit}"
        return result
    artifact_name = case.get("artifact")
    if not isinstance(artifact_name, str):
        return result
    artifact_path = output_dir / artifact_name
    if not artifact_path.is_file():
        result["status"] = "failed"
        result["reason"] = f"Expected artifact was not written: {artifact_name}"
        return result
    artifact = read_json(artifact_path)
    if not isinstance(artifact, dict):
        result["status"] = "failed"
        result["reason"] = f"Expected object artifact: {artifact_name}"
        return result
    for raw_assertion in case.get("assertions", []):
        if not isinstance(raw_assertion, dict):
            raise CorpusError(f"Corpus case {case['id']} has a non-object assertion")
        path = raw_assertion.get("path")
        if not isinstance(path, str) or "equals" not in raw_assertion:
            raise CorpusError(f"Corpus case {case['id']} assertion requires path and equals")
        actual = _nested_value(artifact, path)
        assertion_result = {"path": path, "expected": raw_assertion["equals"], "actual": actual}
        cast_assertions = result["assertions"]
        assert isinstance(cast_assertions, list)
        cast_assertions.append(assertion_result)
        if actual != raw_assertion["equals"]:
            result["status"] = "failed"
            result["reason"] = f"Assertion mismatch at {path}"
            return result
    expected_signal_ids = case.get("expected_signal_ids")
    if expected_signal_ids is not None:
        collection = artifact.get("signals", artifact.get("findings", []))
        if not isinstance(collection, list):
            result["status"] = "failed"
            result["reason"] = "Artifact has no signal/finding list"
            return result
        actual_ids = {
            item["id"]
            for item in collection
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        expected_ids = set(expected_signal_ids)
        result["expected_signal_ids"] = sorted(expected_ids)
        result["actual_signal_ids"] = sorted(actual_ids)
        if expected_ids and not expected_ids.issubset(actual_ids):
            result["status"] = "failed"
            result["reason"] = "Expected signal IDs were not all present"
        elif not expected_ids and actual_ids:
            result["status"] = "failed"
            result["reason"] = "Expected no signal IDs, but artifact contained signals"
    return result


def _markdown_summary(summary: dict[str, object]) -> str:
    """Render a concise local report that preserves every case's claim boundary."""

    cases = summary["cases"]
    assert isinstance(cases, list)
    lines = [
        "# TrustWeave Synthetic Evaluation Corpus Summary",
        "",
        (
            "This local report records only supplied synthetic corpus behavior. It does not "
            "establish runtime enforcement, input authenticity, attack prevention, or general "
            "security efficacy."
        ),
        "",
        "| Case | Operation | Expected exit | Actual exit | Status |",
        "|---|---|---:|---:|---|",
    ]
    for case in cases:
        assert isinstance(case, dict)
        row = (
            f"| `{case['id']}` | `{case['operation']}` | {case['expected_exit']} | "
            f"{case['actual_exit']} | {case['status']} |"
        )
        lines.append(row)
    lines.extend(["", "## Case limits", ""])
    for case in cases:
        assert isinstance(case, dict)
        lines.append(f"- **{case['id']}:** {case['non_claim']}")
    lines.append("")
    return "\n".join(lines)


def run_corpus(corpus_path: Path, output_dir: Path) -> dict[str, object]:
    """Run every validated case into one caller-selected local output directory."""

    corpus = load_document(corpus_path)
    if not isinstance(corpus, dict):
        raise CorpusError("Evaluation corpus root must be an object")
    cases = _validate_corpus(corpus)
    output_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, object]] = []
    for case in cases:
        case_dir = output_dir / str(case["id"])
        case_dir.mkdir(parents=True, exist_ok=True)
        actual_exit, stdout, stderr = _run_case(case, case_dir)
        result = _assert_case(case, case_dir, actual_exit)
        result["stdout"] = stdout
        result["stderr"] = stderr
        results.append(result)
    passed = sum(result["status"] == "passed" for result in results)
    summary: dict[str, object] = {
        "schema_version": "trustweave.dev/evaluation-corpus-summary/v1alpha1",
        "corpus_id": corpus["corpus_id"],
        "corpus_version": corpus["corpus_version"],
        "generated_at": FIXED_GENERATED_AT,
        "summary": {
            "cases": len(results),
            "passed": passed,
            "failed": len(results) - passed,
            "status": "passed" if passed == len(results) else "failed",
        },
        "non_claim": corpus["non_claim"],
        "cases": results,
    }
    write_json(output_dir / "evaluation-corpus-summary.json", summary)
    (output_dir / "evaluation-corpus-summary.md").write_text(
        _markdown_summary(summary), encoding="utf-8"
    )
    return summary


def _parser() -> argparse.ArgumentParser:
    """Build the small local-only corpus runner interface."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus", type=Path, default=DEFAULT_CORPUS, help="Checked-in corpus manifest path."
    )
    parser.add_argument(
        "--output-dir", type=Path, help="Local output directory; defaults to a temporary directory."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="Validate the checked-in local corpus contract without running any case.",
    )
    mode.add_argument(
        "--verify", action="store_true", help="Return non-zero when any corpus expectation fails."
    )
    return parser


def main_runner(argv: list[str] | None = None) -> int:
    """Run the corpus and print a concise local status summary."""

    args = _parser().parse_args(argv)
    corpus_path = args.corpus.resolve()
    try:
        _inside_root(corpus_path.relative_to(ROOT).as_posix())
        if args.check:
            corpus = load_document(corpus_path)
            if not isinstance(corpus, dict):
                raise CorpusError("Evaluation corpus root must be an object")
            cases = _validate_corpus(corpus)
            print(
                "Evaluation corpus contract passed: "
                f"{len(cases)} cases, {corpus['corpus_version']}."
            )
            return 0
        if args.output_dir is None:
            with tempfile.TemporaryDirectory(prefix="trustweave-evaluation-corpus-") as temporary:
                summary = run_corpus(corpus_path, Path(temporary))
        else:
            summary = run_corpus(corpus_path, args.output_dir.resolve())
    except (CorpusError, ValueError, OSError) as error:
        print(f"Evaluation corpus error: {error}")
        return 2
    details = summary["summary"]
    assert isinstance(details, dict)
    print(
        "Evaluation corpus "
        f"{details['status']}: {details['passed']}/{details['cases']} cases passed; "
        f"{details['failed']} failed."
    )
    return 0 if details["status"] == "passed" or not args.verify else 1


if __name__ == "__main__":
    raise SystemExit(main_runner())
