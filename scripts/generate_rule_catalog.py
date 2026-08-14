#!/usr/bin/env python3
"""Generate the built-in rule catalog from TrustWeave's authoritative registry."""

from __future__ import annotations

import argparse
from pathlib import Path

from trustweave.rules import RULES

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "site" / "RULE_CATALOG.md"


def _cell(value: str) -> str:
    """Keep generated Markdown table cells structurally safe and deterministic."""

    return value.replace("|", "\\|").replace("\n", " ")


def render() -> str:
    """Render stable built-in reviewer guidance with no clocks or external inputs."""

    rows = [
        "| Identifier | Evidence kind | Title | Local trigger / rationale | Reviewer action |",
        "|---|---|---|---|---|",
    ]
    for identifier, rule in sorted(RULES.items()):
        rows.append(
            "| "
            f"`{identifier}` | `{_cell(rule.evidence_kind)}` | {_cell(rule.title)} | "
            f"{_cell(rule.rationale)} | {_cell(rule.remediation)} |"
        )
    return (
        "# Built-in Rule Catalog\n\n"
        "> This reference is generated from TrustWeave's immutable built-in rule registry. "
        "Regenerate it with `python scripts/generate_rule_catalog.py`; do not edit the "
        "table manually.\n\n"
        "TrustWeave finding identifiers are stable labels for **review of supplied local "
        "declarations and evidence metadata**. They do not establish a vulnerability, incident, "
        "runtime exploit path, deployed control state, or authorization outcome. User-supplied "
        "policy-rule identifiers are declarations and are not included in this catalog.\n\n"
        + "\n".join(rows)
        + "\n\n"
        "## Risk-review states\n\n"
        "Risk lifecycle output uses `risk_state` rather than a rule identifier. `new`, "
        "`expired_baseline`, and `expired_suppression` remain active reviewer obligations; "
        "`baselined` and `suppressed` are explicit, expiry-limited local decisions. These states "
        "neither remediate nor waive a security condition. See the "
        "[repository risk-management guide]("
        "https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/RISK_MANAGEMENT.md) "
        "for fingerprint, expiry, and decision-document contracts.\n"
    )


def main() -> int:
    """Write or verify the deterministic generated rule catalog."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="Fail when the tracked generated catalog is stale."
    )
    arguments = parser.parse_args()
    expected = render()
    if arguments.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != expected:
            print(f"Generated rule catalog is stale: {OUTPUT}")
            return 1
        return 0
    OUTPUT.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
