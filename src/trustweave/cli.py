"""Thin public CLI facade for deterministic local TrustWeave commands."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import Never

from trustweave.commands._shared import (
    EXIT_INPUT_OUTPUT,
    EXIT_INTERNAL,
    EXIT_INVALID_INPUT,
    EXIT_REVIEW,
    EXIT_SUCCESS,
)
from trustweave.commands.registry import dispatch, register_all
from trustweave.models import InputOutputError, ValidationError
from trustweave.provenance import generation_timestamp

__all__ = [
    "EXIT_INPUT_OUTPUT",
    "EXIT_INTERNAL",
    "EXIT_INVALID_INPUT",
    "EXIT_REVIEW",
    "EXIT_SUCCESS",
    "main",
]


class _ArgumentParser(argparse.ArgumentParser):
    """Expose invalid command syntax through TrustWeave's validation contract."""

    def error(self, message: str) -> Never:
        raise ValidationError(message)


def _parser() -> argparse.ArgumentParser:
    """Build the authoritative public command parser from focused registrations."""

    parser = _ArgumentParser(
        prog="trustweave",
        description="Local-first security build evidence for declared AI agent trust boundaries.",
    )
    parser.add_argument(
        "--generated-at",
        help=(
            "Explicit ISO 8601 provenance timestamp; defaults to SOURCE_DATE_EPOCH or current UTC."
        ),
    )
    parser.add_argument("--debug", action="store_true", help="Show a traceback for failures.")
    register_all(parser.add_subparsers(dest="command", required=True))
    return parser


def _debug_requested(argv: Sequence[str] | None) -> bool:
    arguments = sys.argv[1:] if argv is None else argv
    return "--debug" in arguments


def _error(message: str) -> None:
    print(message, file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    """Run a declared local command with stable, machine-usable exit codes."""

    debug = _debug_requested(argv)
    try:
        args = _parser().parse_args(argv)
        debug = args.debug
        message, code = dispatch(args, generation_timestamp(args.generated_at))
        print(message)
        return code
    except ValidationError as error:
        if debug:
            raise
        _error(f"Validation error: {error}")
        return EXIT_INVALID_INPUT
    except InputOutputError as error:
        if debug:
            raise
        _error(f"Input/output error: {error}")
        return EXIT_INPUT_OUTPUT
    except OSError as error:
        if debug:
            raise
        _error(f"Input/output error: {error}")
        return EXIT_INPUT_OUTPUT
    except Exception as error:
        if debug:
            raise
        _error(f"Internal error: {type(error).__name__}: {error}")
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
