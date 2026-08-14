"""Shared deterministic command-layer constants and local configuration resolution."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from trustweave.config import find_project_config, load_project_config
from trustweave.models import InputOutputError, ValidationError

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
UNSIGNED_STATEMENT_FILE = "unsigned-statement.json"
RISK_REVIEW_FILE = "risk-review.json"
RISK_REVIEW_REPORT_FILE = "risk-review.md"
CHAIN_REVIEW_FILE = "chain-review.json"
CHAIN_REVIEW_REPORT_FILE = "chain-review.md"

EXIT_SUCCESS = 0
EXIT_REVIEW = 1
EXIT_INVALID_INPUT = 2
EXIT_INPUT_OUTPUT = 3
EXIT_INTERNAL = 4


def configured_paths(
    config_path: Path | None,
    values: Mapping[str, Path | None],
) -> dict[str, Path]:
    """Resolve explicit command paths or a single local ``trustweave.toml`` document."""

    missing = [name for name, value in values.items() if value is None]
    if not missing:
        return {name: value for name, value in values.items() if value is not None}
    if config_path is None:
        try:
            path = find_project_config(Path.cwd())
        except InputOutputError as error:
            raise ValidationError(
                "required command paths were not supplied and no local trustweave.toml was "
                "discovered"
            ) from error
    else:
        path = config_path
    config = load_project_config(path)
    resolved: dict[str, Path] = {}
    for name, value in values.items():
        selected = value
        if selected is None:
            configured = config.get(name)
            if configured is None:
                raise ValidationError(
                    f"{name} is required as a command argument or tool.trustweave.{name} in {path}"
                )
            selected = Path(configured)
            if not selected.is_absolute():
                selected = path.parent / selected
        resolved[name] = selected
    return resolved
