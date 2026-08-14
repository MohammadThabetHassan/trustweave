"""Strict local project configuration helpers with no environment or network access."""

from __future__ import annotations

import tomllib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, TypeAlias

from trustweave.io import write_text
from trustweave.models import InputOutputError, ValidationError, reject_unknown_fields

CONFIG_FILE_NAME = "trustweave.toml"
MAX_CONFIG_DISCOVERY_PARENTS = 8
MAX_ENABLED_STAGES = 16
ConfigValue: TypeAlias = str | bool | tuple[str, ...]

PATH_FIELDS = frozenset(
    {
        "manifest",
        "policy",
        "scenarios",
        "chain_manifest",
        "baseline_bundle",
        "candidate_bundle",
        "trace",
        "mcp_profile",
        "risk_baseline",
        "suppressions",
        "output_dir",
        "sarif_output",
    }
)
VALID_FAILURE_THRESHOLDS = frozenset(
    {"critical", "high", "medium", "low", "info", "review", "none"}
)
VALID_WORKFLOW_STAGES = frozenset(
    {
        "validate",
        "scan",
        "scenarios",
        "policy_review",
        "policy_coverage",
        "diff",
        "trace_review",
        "mcp_profile_review",
        "chain_review",
        "risk",
        "sarif",
        "attestation",
        "report",
        "summary",
    }
)
CONFIG_FIELDS = PATH_FIELDS | {"failure_threshold", "enabled_stages", "reproducible"}

CONFIG_TEMPLATE = (
    "# Local TrustWeave project configuration\n"
    "# Paths are relative to this file. No remote includes, environment interpolation, "
    "or secrets.\n"
    "[tool.trustweave]\n"
    'manifest = "examples/support-agent.manifest.json"\n'
    'policy = "policies/default-policy.json"\n'
    'scenarios = "scenarios/default-scenarios.json"\n'
    'output_dir = "artifacts"\n'
    'failure_threshold = "high"\n'
    'enabled_stages = ["scan", "scenarios", "policy_review", "attestation", "report"]\n'
    "reproducible = true\n"
)


def find_project_config(start: Path, *, max_parents: int = MAX_CONFIG_DISCOVERY_PARENTS) -> Path:
    """Find the nearest configuration within an explicit bounded local parent walk."""

    if max_parents < 0:
        raise ValidationError("config discovery max_parents must be non-negative")
    directory = start.resolve()
    if directory.is_file():
        directory = directory.parent
    for distance, candidate_directory in enumerate((directory, *directory.parents)):
        if distance > max_parents:
            break
        candidate = candidate_directory / CONFIG_FILE_NAME
        if candidate.is_file():
            return candidate
    raise InputOutputError(
        f"No {CONFIG_FILE_NAME} was found within {max_parents} parent directories from: {start}"
    )


def init_project(directory: Path) -> Path:
    """Create an opt-in local configuration template without replacing an existing file."""

    path = directory / CONFIG_FILE_NAME
    if path.exists():
        raise InputOutputError(f"Refusing to overwrite existing project configuration: {path}")
    return write_text(path, CONFIG_TEMPLATE)


def _string(value: Any, path: str) -> str:
    """Validate one non-empty, local-only scalar string setting."""

    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{path} must be a non-empty string")
    if "\x00" in value:
        raise ValidationError(f"{path} must not contain a null byte")
    return value.strip()


def _enabled_stages(value: Any) -> tuple[str, ...]:
    """Validate the bounded, explicit local workflow stage selection."""

    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValidationError("tool.trustweave.enabled_stages must be a list of stage names")
    if not value or len(value) > MAX_ENABLED_STAGES:
        raise ValidationError(
            "tool.trustweave.enabled_stages must contain between 1 and "
            f"{MAX_ENABLED_STAGES} stage names"
        )
    stages = tuple(_string(stage, "tool.trustweave.enabled_stages[]") for stage in value)
    unknown = sorted(set(stages) - VALID_WORKFLOW_STAGES)
    if unknown:
        raise ValidationError(
            "tool.trustweave.enabled_stages contains unsupported stages: " + ", ".join(unknown)
        )
    if len(set(stages)) != len(stages):
        raise ValidationError("tool.trustweave.enabled_stages must not contain duplicates")
    return stages


def load_project_config(path: Path) -> Mapping[str, ConfigValue]:
    """Load one strict, local-only TOML configuration without interpolation or includes."""

    try:
        document: Any = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise InputOutputError(f"Project configuration does not exist: {path}") from error
    except UnicodeDecodeError as error:
        raise InputOutputError(f"Project configuration is not valid UTF-8: {path}") from error
    except tomllib.TOMLDecodeError as error:
        raise ValidationError(f"Project configuration is invalid TOML: {error}") from error
    if not isinstance(document, Mapping):
        raise ValidationError("project configuration must be a TOML table")
    tool = document.get("tool")
    if not isinstance(tool, Mapping):
        raise ValidationError("project configuration requires [tool.trustweave]")
    config = tool.get("trustweave")
    if not isinstance(config, Mapping):
        raise ValidationError("project configuration requires [tool.trustweave]")
    reject_unknown_fields(config, set(CONFIG_FIELDS), "tool.trustweave")

    result: dict[str, ConfigValue] = {}
    for key, value in config.items():
        path_name = f"tool.trustweave.{key}"
        if key in PATH_FIELDS:
            result[key] = _string(value, path_name)
        elif key == "failure_threshold":
            threshold = _string(value, path_name)
            if threshold not in VALID_FAILURE_THRESHOLDS:
                raise ValidationError(
                    f"{path_name} must be one of {sorted(VALID_FAILURE_THRESHOLDS)}"
                )
            result[key] = threshold
        elif key == "enabled_stages":
            result[key] = _enabled_stages(value)
        elif key == "reproducible":
            if not isinstance(value, bool):
                raise ValidationError(f"{path_name} must be a boolean")
            result[key] = value
        else:  # pragma: no cover - reject_unknown_fields guards the contract above.
            raise ValidationError(f"tool.trustweave: unsupported field {key!r}")
    return result
