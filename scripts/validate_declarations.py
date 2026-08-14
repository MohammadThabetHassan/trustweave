#!/usr/bin/env python3
"""Validate staged local TrustWeave declarations without producing artifacts."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from trustweave.chain import review_declared_chains
from trustweave.config import load_project_config
from trustweave.io import load_document
from trustweave.models import InputOutputError, ValidationError, parse_manifest, parse_policy
from trustweave.scenarios import parse_scenarios

DocumentValidator = Callable[[Mapping[str, Any]], object]


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate local TrustWeave declarations without producing artifacts."
    )
    parser.add_argument(
        "kind",
        choices=("chain-manifest", "config", "manifest", "policy", "scenarios"),
        help="Declaration contract to validate.",
    )
    parser.add_argument("paths", nargs="+", type=Path, help="One or more local declaration paths.")
    return parser.parse_args()


def _validate_document(validator: DocumentValidator, path: Path) -> None:
    validator(load_document(path))


def main() -> int:
    """Validate every supplied local declaration and report errors without side effects."""

    arguments = _parse_arguments()
    validators: dict[str, DocumentValidator] = {
        "chain-manifest": review_declared_chains,
        "manifest": parse_manifest,
        "policy": parse_policy,
        "scenarios": parse_scenarios,
    }
    for path in arguments.paths:
        try:
            if arguments.kind == "config":
                load_project_config(path)
            else:
                _validate_document(validators[arguments.kind], path)
        except (InputOutputError, OSError, ValidationError, ValueError) as error:
            print(f"{path}: {error}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
