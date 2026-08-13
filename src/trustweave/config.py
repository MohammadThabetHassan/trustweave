"""Strict local project configuration helpers with no environment or network access."""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from trustweave.io import write_text
from trustweave.models import InputOutputError, ValidationError, reject_unknown_fields

CONFIG_FILE_NAME = "trustweave.toml"
CONFIG_TEMPLATE = (
    "# Local TrustWeave project configuration\n"
    "[tool.trustweave]\n"
    'manifest = "examples/support-agent.manifest.json"\n'
    'policy = "policies/default-policy.json"\n'
    'scenarios = "scenarios/default-scenarios.json"\n'
    'output_dir = "artifacts"\n'
)


def init_project(directory: Path) -> Path:
    """Create an opt-in local configuration template without replacing an existing file."""

    path = directory / CONFIG_FILE_NAME
    if path.exists():
        raise InputOutputError(f"Refusing to overwrite existing project configuration: {path}")
    return write_text(path, CONFIG_TEMPLATE)


def load_project_config(path: Path) -> Mapping[str, str]:
    """Load one bounded local TOML configuration document for future explicit CLI orchestration."""

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
    allowed = {"manifest", "policy", "scenarios", "output_dir"}
    reject_unknown_fields(config, allowed, "tool.trustweave")
    result: dict[str, str] = {}
    for key, value in config.items():
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"tool.trustweave.{key} must be a non-empty string")
        result[key] = value
    return result
