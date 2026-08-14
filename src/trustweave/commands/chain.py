"""Bounded declared-chain review command."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from trustweave.chain import render_chain_review, review_declared_chains
from trustweave.commands._shared import CHAIN_REVIEW_FILE, CHAIN_REVIEW_REPORT_FILE, EXIT_REVIEW
from trustweave.io import load_document, write_json, write_text


def register(subcommands: Any) -> None:
    """Register bounded declared-chain analysis."""

    chain_check = subcommands.add_parser(
        "chain-check",
        help=(
            "Review a supplied declared trust-boundary graph without runtime discovery or "
            "execution."
        ),
    )
    chain_check.add_argument("--input", type=Path, required=True, help="Local chain-manifest JSON.")
    chain_check.add_argument(
        "--output-dir", type=Path, default=Path("artifacts"), help="Artifact directory."
    )
    chain_check.add_argument("--max-nodes", type=int, default=1000, help="Maximum declared nodes.")
    chain_check.add_argument("--max-paths", type=int, default=1000, help="Maximum emitted paths.")
    chain_check.add_argument("--max-edges", type=int, default=5000, help="Maximum traversed edges.")
    chain_check.add_argument(
        "--max-depth", type=int, default=100, help="Maximum declared path depth."
    )
    chain_check.add_argument(
        "--max-states", type=int, default=5000, help="Maximum propagation states."
    )
    chain_check.add_argument(
        "--exit-on-review", action="store_true", help="Return status 1 when review findings exist."
    )


def handle(args: argparse.Namespace, generated_at: str) -> tuple[str, int]:
    """Create local chain-review JSON and Markdown evidence from a supplied graph."""

    review = review_declared_chains(
        load_document(args.input),
        generated_at,
        max_nodes=args.max_nodes,
        max_paths=args.max_paths,
        max_edges=args.max_edges,
        max_depth=args.max_depth,
        max_states=args.max_states,
    )
    json_path = write_json(args.output_dir / CHAIN_REVIEW_FILE, review)
    markdown_path = write_text(
        args.output_dir / CHAIN_REVIEW_REPORT_FILE, render_chain_review(review)
    )
    code = EXIT_REVIEW if args.exit_on_review and review["findings"] else 0
    return f"Wrote declared chain review: {json_path} and {markdown_path}", code
