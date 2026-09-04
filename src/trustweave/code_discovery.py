"""Build the reviewable artifact describing an agent's discovered code surface.

This module turns the analyzer's observations into a deterministic document: what was
found, what the declared manifest says, where the two disagree, and what a reviewer still
has to decide. It proposes; it never authorizes.

Coverage is reported as integer basis points computed by floor division, so the artifact
holds no floating-point value and two runs over the same tree are byte-identical.
"""

from __future__ import annotations

import difflib
from typing import Any, Final

from trustweave.code_analysis import DiscoveredTool, analyze_sources
from trustweave.code_catalog import (
    CAPABILITY_BY_ACTION_CLASS,
    CATALOG_VERSION,
    REVIEW_PLACEHOLDER,
    UNKNOWN_ACTION_CLASS,
    UNKNOWN_TRUST,
)
from trustweave.code_sources import SourceCollection
from trustweave.models import AgentManifest
from trustweave.provenance import add_generated_at
from trustweave.rules import finding_for_rule

CODE_DISCOVERY_SCHEMA_VERSION: Final[str] = "trustweave.dev/code-discovery/v1alpha1"

MANIFEST_DRAFT_SCHEMA_VERSION: Final[str] = "trustweave.dev/v1alpha1"

EVIDENCE_LIMITS: Final[tuple[str, ...]] = (
    (
        "TrustWeave parsed local Python source with the standard library AST. It did not "
        "import, compile, install, execute, or resolve dependencies of the analyzed project."
    ),
    (
        "Proposed action classes come from a bounded, versioned symbol catalog. They are "
        "review proposals, not authorizations, and a proposal is never a security verdict."
    ),
    (
        "Every source trust in the draft is emitted as unknown. TrustWeave does not infer "
        "trust, data classification, or authorization from code, names, or docstrings."
    ),
    (
        "The manifest draft is intentionally not a valid Agent Security Manifest until a "
        "reviewer resolves every placeholder it contains."
    ),
    (
        "Declaration coverage measures name agreement between discovered and declared "
        "tools. It does not establish that either the code or the manifest is complete."
    ),
    (
        "Discovery is bounded. Dynamic dispatch, unresolved imports, and exhausted budgets "
        "are reported as unknown rather than as a clean result."
    ),
    (
        "AST shapes vary between Python interpreter versions, so a run on a different "
        "interpreter may resolve a different symbol set."
    ),
)

_REASON_MESSAGES: Final[dict[str, str]] = {
    "UNRESOLVED_CALLEE": "a call target could not be resolved to an imported symbol",
    "DYNAMIC_DISPATCH": "the implementation selects behaviour dynamically",
    "NONLITERAL_ARGUMENT": "an argument that decides the effect is not a literal",
    "BODY_UNAVAILABLE": "no implementation body could be located",
    "BUDGET_EXHAUSTED": "the analysis budget was exhausted before the body was covered",
    "LEXICAL_ONLY": "only naming evidence was present, with no observed behaviour",
}


def _tool_entry(tool: DiscoveredTool, declared_names: set[str] | None) -> dict[str, Any]:
    proposed = tool.proposed_action_class()
    entry: dict[str, Any] = {
        "name": tool.name,
        "framework": tool.framework,
        **({"implementation": tool.implementation} if tool.implementation is not None else {}),
        "location": {"file": tool.file, "line": str(tool.line)},
        "proposed_action_class": proposed,
        "confidence": tool.confidence(),
        "budget_state": tool.budget_state,
        "signals": [
            {
                "action_class": signal.action_class,
                "symbol": signal.symbol,
                "file": signal.file,
                "line": str(signal.line),
                "via": list(signal.via),
            }
            for signal in tool.signals
        ],
    }
    if tool.reasons:
        entry["reasons"] = sorted(tool.reasons)
    capability = CAPABILITY_BY_ACTION_CLASS.get(proposed)
    if capability:
        entry["proposed_capabilities"] = [capability]
    if declared_names is not None:
        entry["declared_in_manifest"] = tool.name in declared_names
    return entry


def _drift(tools: list[DiscoveredTool], manifest: AgentManifest | None) -> dict[str, Any]:
    if manifest is None:
        return {"manifest_supplied": False, "coverage_status": "not_applicable"}

    declared = sorted({tool.name for tool in manifest.tools})
    discovered = sorted({tool.name for tool in tools})
    matched = sorted(set(declared) & set(discovered))
    missing = sorted(set(discovered) - set(declared))
    absent = sorted(set(declared) - set(discovered))

    renames: list[dict[str, str]] = []
    for name in absent:
        close = difflib.get_close_matches(name, missing, n=1, cutoff=0.8)
        if close:
            renames.append({"declared": name, "discovered": close[0]})

    drift: dict[str, Any] = {
        "manifest_supplied": True,
        "tools_declared": len(declared),
        "tools_discovered": len(discovered),
        "tools_matched": len(matched),
        "missing_from_manifest": missing,
        "declared_not_found_in_code": absent,
        "probable_renames": renames,
    }
    if discovered:
        basis_points = (len(matched) * 10000) // len(discovered)
        drift["coverage_status"] = "measured"
        drift["declaration_coverage_basis_points"] = basis_points
        drift["declaration_coverage_percent"] = f"{basis_points / 100:.2f}"
    else:
        drift["coverage_status"] = "not_applicable"
    return drift


def _manifest_draft(tools: list[DiscoveredTool]) -> dict[str, Any]:
    return {
        "schema_version": MANIFEST_DRAFT_SCHEMA_VERSION,
        "name": f"{REVIEW_PLACEHOLDER}_DISCOVERED_AGENT",
        "description": f"{REVIEW_PLACEHOLDER}: describe this agent before using this draft.",
        "sources": [
            {
                "name": f"{REVIEW_PLACEHOLDER}_source",
                "trust": UNKNOWN_TRUST,
                "data_classification": REVIEW_PLACEHOLDER,
                "description": (
                    "TrustWeave does not infer trust from code. A reviewer must name every "
                    "ingress point and assign its trust."
                ),
            }
        ],
        "tools": [
            {
                "name": tool.name,
                "action_class": tool.proposed_action_class(),
                "capabilities": [],
                "description": f"{REVIEW_PLACEHOLDER}: describe this tool.",
            }
            for tool in tools
        ],
        "flows": [],
        "review_required": [
            (
                "Assign every source trust: trusted, untrusted, or conditional. TrustWeave "
                "emitted unknown and did not guess."
            ),
            "Confirm or correct every proposed action_class, and resolve every unknown.",
            "Add capabilities, data classifications, and flows before using this as a manifest.",
        ],
    }


def _findings(
    tools: list[DiscoveredTool],
    problems: list[dict[str, str]],
    drift: dict[str, Any],
    manifest: AgentManifest | None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    declared_classes = {tool.name: tool.action_class for tool in manifest.tools} if manifest else {}

    for tool in tools:
        subject = {"tool": tool.name, "file": tool.file}
        location = {"file": tool.file, "line": str(tool.line)}
        if "BODY_UNAVAILABLE" in tool.reasons:
            findings.append(
                finding_for_rule(
                    "TW-CODE-001",
                    "review",
                    f"No implementation body was located for discovered tool {tool.name}.",
                    subject=subject,
                    location=location,
                )
            )
        if "BUDGET_EXHAUSTED" in tool.reasons:
            findings.append(
                finding_for_rule(
                    "TW-CODE-006",
                    "review",
                    f"Analysis of {tool.name} stopped before the body was fully covered.",
                    subject=subject,
                    location=location,
                )
            )
        refusals = sorted(tool.reasons - {"BODY_UNAVAILABLE", "BUDGET_EXHAUSTED"})
        if refusals:
            detail = "; ".join(_REASON_MESSAGES.get(reason, reason) for reason in refusals)
            findings.append(
                finding_for_rule(
                    "TW-CODE-005",
                    "review",
                    f"Action class for {tool.name} was not proposed because {detail}.",
                    subject=subject,
                    location=location,
                    properties={"reasons": refusals},
                )
            )
        declared = declared_classes.get(tool.name)
        proposed = tool.proposed_action_class()
        if declared and proposed != UNKNOWN_ACTION_CLASS and declared != proposed:
            findings.append(
                finding_for_rule(
                    "TW-CODE-002",
                    "review",
                    (
                        f"Tool {tool.name} is declared {declared} but its observed effects "
                        f"propose {proposed}."
                    ),
                    subject=subject,
                    location=location,
                    properties={"declared": declared, "proposed": proposed},
                )
            )

    for name in drift.get("missing_from_manifest", []):
        findings.append(
            finding_for_rule(
                "TW-CODE-003",
                "review",
                f"Tool {name} was found in the analyzed source but is not declared.",
                subject={"tool": name},
            )
        )
    for name in drift.get("declared_not_found_in_code", []):
        findings.append(
            finding_for_rule(
                "TW-CODE-004",
                "review",
                f"Declared tool {name} was not found in the analyzed source.",
                subject={"tool": name},
            )
        )
    for problem in problems:
        findings.append(
            finding_for_rule(
                "TW-CODE-008",
                "review",
                f"Local source file {problem['file']} could not be analyzed.",
                subject={"file": problem["file"]},
                properties={"reason": problem["reason"]},
            )
        )

    findings.sort(key=lambda item: (item["id"], item["message"]))
    return findings


def review_code_discovery(
    collection: SourceCollection,
    manifest: AgentManifest | None,
    generated_at: str | None,
) -> dict[str, Any]:
    """Review one local Python source tree and return the discovery artifact."""

    tools, problems = analyze_sources(collection)
    # Files that failed to parse were read and then rejected; files that were skipped were
    # never read at all. Both belong in problems, but only the first were ever counted in
    # collection.files, so the two populations must not be conflated when reporting how
    # many files were analyzed.
    parse_failures = len(problems)
    for skipped in collection.skipped:
        problems.append({"file": skipped.relative_path, "reason": skipped.reason})
    problems.sort(key=lambda problem: (problem["file"], problem["reason"]))

    drift = _drift(tools, manifest)
    declared_names = {tool.name for tool in manifest.tools} if manifest else None
    findings = _findings(tools, problems, drift, manifest)

    unknown = sum(1 for tool in tools if tool.proposed_action_class() == UNKNOWN_ACTION_CLASS)
    review: dict[str, Any] = {
        "schema_version": CODE_DISCOVERY_SCHEMA_VERSION,
        "source": {
            "root_name": collection.root_name,
            "files_analyzed": len(collection.files) - parse_failures,
            "files_skipped": len(problems),
            "catalog_version": CATALOG_VERSION,
        },
        "summary": {
            "tools_discovered": len(tools),
            "tools_classified": len(tools) - unknown,
            "tools_unknown": unknown,
            "review_findings": len(findings),
            "status": "review_required" if findings else "clear",
        },
        "tools": [_tool_entry(tool, declared_names) for tool in tools],
        "drift": drift,
        "manifest_draft": _manifest_draft(tools),
        "findings": findings,
        "limits": list(EVIDENCE_LIMITS),
    }
    return add_generated_at(review, generated_at)
