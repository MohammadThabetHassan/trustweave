"""Command registration and deterministic dispatch for the thin CLI facade."""

from __future__ import annotations

import argparse
from collections import OrderedDict
from typing import Any

from trustweave.commands import chain, ci, config, evidence, importers, policy, risk, scan, test

COMMAND_ORDER = (
    "init",
    "config",
    "schema",
    "ci",
    "scan",
    "test",
    "explain",
    "why",
    "attest",
    "report",
    "verify",
    "diff",
    "chain-check",
    "policy-check",
    "trace-review",
    "framework-import",
    "mcp-scaffold",
    "mcp-import",
    "mcp-profile-check",
    "statement",
    "baseline",
    "suppressions",
    "risk-check",
    "sarif",
)


def register_all(subcommands: Any) -> None:
    """Register every supported top-level command in stable public-help order."""

    config.register(subcommands)
    ci.register(subcommands)
    scan.register(subcommands)
    test.register(subcommands)
    evidence.register(subcommands)
    chain.register(subcommands)
    policy.register(subcommands)
    importers.register(subcommands)
    risk.register(subcommands)

    choices = subcommands.choices
    ordered_choices = OrderedDict((name, choices[name]) for name in COMMAND_ORDER)
    subcommands.choices = ordered_choices
    subcommands._name_parser_map = ordered_choices
    subcommands._choices_actions.sort(key=lambda action: COMMAND_ORDER.index(action.dest))


def dispatch(args: argparse.Namespace, generated_at: str) -> tuple[str, int]:
    """Execute exactly one parsed command without any ambient runtime discovery or execution."""

    if args.command in {"init", "config", "schema"}:
        return config.handle(args)
    if args.command == "ci":
        return ci.handle(args, generated_at)
    if args.command == "scan":
        return scan.handle(args, generated_at)
    if args.command in {"test", "explain", "why", "trace-review"}:
        return test.handle(args, generated_at)
    if args.command in {"attest", "report", "verify", "diff", "statement", "sarif"}:
        return evidence.handle(args, generated_at)
    if args.command == "chain-check":
        return chain.handle(args, generated_at)
    if args.command == "policy-check":
        return policy.handle(args, generated_at)
    if args.command in {"framework-import", "mcp-scaffold", "mcp-import", "mcp-profile-check"}:
        return importers.handle(args, generated_at)
    if args.command in {"baseline", "suppressions", "risk-check"}:
        return risk.handle(args, generated_at)
    raise RuntimeError(f"Unsupported command: {args.command}")
