"""Deterministic comparison of two TrustWeave Agent Security Bundles."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from trustweave.models import ValidationError
from trustweave.provenance import add_generated_at

BUNDLE_SCHEMA_VERSION = "trustweave.dev/bundle/v1alpha1"
REVIEW_ACTION_CLASSES = frozenset({"sensitive", "external"})


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> Sequence[Any]:
    return value if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) else []


def _items_by_name(items: Sequence[Any], label: str) -> dict[str, Mapping[str, Any]]:
    indexed: dict[str, Mapping[str, Any]] = {}
    for item in items:
        mapped = _mapping(item)
        name = mapped.get("name")
        if not isinstance(name, str) or not name:
            raise ValidationError(f"{label} must contain named objects")
        if name in indexed:
            raise ValidationError(f"{label} contains duplicate item name: {name}")
        indexed[name] = mapped
    return indexed


def _flow_key(flow: Mapping[str, Any]) -> tuple[str, str, str]:
    source = flow.get("source")
    tool = flow.get("tool")
    purpose = flow.get("purpose")
    if not isinstance(source, str) or not source:
        raise ValidationError("bundle findings must contain a named source")
    if not isinstance(tool, str) or not tool:
        raise ValidationError("bundle findings must contain a named tool")
    if not isinstance(purpose, str) or not purpose:
        raise ValidationError("bundle findings must contain a flow purpose")
    return source, tool, purpose


def _findings_by_key(bundle: Mapping[str, Any]) -> dict[tuple[str, str, str], Mapping[str, Any]]:
    indexed: dict[tuple[str, str, str], Mapping[str, Any]] = {}
    for item in _sequence(bundle.get("findings")):
        finding = _mapping(item)
        flow = _mapping(finding.get("flow"))
        key = _flow_key(flow)
        if key in indexed:
            raise ValidationError(f"bundle contains duplicate finding for {key}")
        indexed[key] = finding
    return indexed


def _assert_bundle(bundle: Mapping[str, Any], label: str) -> None:
    if bundle.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise ValidationError(f"{label} must use {BUNDLE_SCHEMA_VERSION}")
    manifest = _mapping(bundle.get("manifest"))
    if not manifest:
        raise ValidationError(f"{label} is missing a manifest")


def _named_changes(
    base: Mapping[str, Mapping[str, Any]], head: Mapping[str, Mapping[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    added_names = sorted(set(head) - set(base))
    removed_names = sorted(set(base) - set(head))
    changed_names = sorted(name for name in set(base) & set(head) if base[name] != head[name])
    return {
        "added": [{"name": name, "after": head[name]} for name in added_names],
        "removed": [{"name": name, "before": base[name]} for name in removed_names],
        "changed": [
            {"name": name, "before": base[name], "after": head[name]} for name in changed_names
        ],
    }


def _capabilities(tool: Mapping[str, Any], label: str) -> set[str]:
    capabilities: set[str] = set()
    for capability in _sequence(tool.get("capabilities")):
        if not isinstance(capability, str) or not capability:
            raise ValidationError(f"{label} must contain non-empty capability strings")
        capabilities.add(capability)
    return capabilities


def _capability_changes(
    tool_changes: Mapping[str, Sequence[Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for item in tool_changes["changed"]:
        name = item.get("name")
        if not isinstance(name, str) or not name:
            raise ValidationError("changed tool must contain a name")
        before = _mapping(item.get("before"))
        after = _mapping(item.get("after"))
        added = sorted(
            _capabilities(after, f"head tool {name}.capabilities")
            - _capabilities(before, f"base tool {name}.capabilities")
        )
        removed = sorted(
            _capabilities(before, f"base tool {name}.capabilities")
            - _capabilities(after, f"head tool {name}.capabilities")
        )
        if added or removed:
            changes.append(
                {
                    "name": name,
                    "action_class": after.get("action_class", "unknown"),
                    "added": added,
                    "removed": removed,
                }
            )
    return changes


def _review_signals(
    tool_changes: Mapping[str, Sequence[Mapping[str, Any]]],
    capability_changes: Sequence[Mapping[str, Any]],
    changed_findings: Sequence[Mapping[str, Any]],
) -> list[dict[str, str]]:
    signals: list[dict[str, str]] = []
    for item in list(tool_changes["added"]) + list(tool_changes["changed"]):
        after = _mapping(item.get("after"))
        action_class = after.get("action_class")
        name = item.get("name", "unknown")
        if action_class in REVIEW_ACTION_CLASSES:
            signals.append(
                {
                    "severity": "review",
                    "id": "TW-DIFF-001",
                    "message": (
                        f"Tool {name} is newly introduced or changed with action class "
                        f"{action_class}; review its capability and policy coverage."
                    ),
                }
            )

    for change in capability_changes:
        action_class = change.get("action_class")
        added = _sequence(change.get("added"))
        name = change.get("name", "unknown")
        if action_class in REVIEW_ACTION_CLASSES and added:
            capability_list = ", ".join(
                capability for capability in added if isinstance(capability, str)
            )
            signals.append(
                {
                    "severity": "review",
                    "id": "TW-DIFF-003",
                    "message": (
                        f"Tool {name} gained sensitive or external capabilities: "
                        f"{capability_list}. Review least-privilege scope and policy coverage."
                    ),
                }
            )

    for finding in changed_findings:
        source = _mapping(finding.get("source"))
        tool = _mapping(finding.get("tool"))
        if (
            source.get("trust") == "untrusted"
            and tool.get("action_class") in REVIEW_ACTION_CLASSES
            and finding.get("decision") != "deny"
        ):
            signals.append(
                {
                    "severity": "review",
                    "id": "TW-DIFF-002",
                    "message": (
                        "The head bundle declares an untrusted-input path to a sensitive or "
                        "external tool that is not denied; review the policy decision and "
                        "human-control boundary."
                    ),
                }
            )
    return signals


def diff_bundles(
    base_bundle: Mapping[str, Any], head_bundle: Mapping[str, Any], generated_at: str | None = None
) -> dict[str, Any]:
    """Compare bundle evidence with optional application-layer provenance."""

    _assert_bundle(base_bundle, "base bundle")
    _assert_bundle(head_bundle, "head bundle")
    base_manifest = _mapping(base_bundle.get("manifest"))
    head_manifest = _mapping(head_bundle.get("manifest"))

    source_changes = _named_changes(
        _items_by_name(_sequence(base_manifest.get("sources")), "base sources"),
        _items_by_name(_sequence(head_manifest.get("sources")), "head sources"),
    )
    tool_changes = _named_changes(
        _items_by_name(_sequence(base_manifest.get("tools")), "base tools"),
        _items_by_name(_sequence(head_manifest.get("tools")), "head tools"),
    )

    base_findings = _findings_by_key(base_bundle)
    head_findings = _findings_by_key(head_bundle)
    added_paths = sorted(set(head_findings) - set(base_findings))
    removed_paths = sorted(set(base_findings) - set(head_findings))
    changed_paths = sorted(
        key
        for key in set(base_findings) & set(head_findings)
        if base_findings[key].get("decision") != head_findings[key].get("decision")
        or base_findings[key].get("rule_id") != head_findings[key].get("rule_id")
    )
    path_changes: dict[str, list[Any]] = {
        "added": [head_findings[key] for key in added_paths],
        "removed": [base_findings[key] for key in removed_paths],
        "decision_changed": [
            {"key": list(key), "before": base_findings[key], "after": head_findings[key]}
            for key in changed_paths
        ],
    }
    capability_changes = _capability_changes(tool_changes)
    review_relevant_findings = [head_findings[key] for key in added_paths + changed_paths]
    signals = _review_signals(tool_changes, capability_changes, review_relevant_findings)

    diff: dict[str, object] = {
        "schema_version": "trustweave.dev/bundle-diff/v1alpha1",
        "base": {
            "agent": base_manifest.get("name", "unknown"),
            "bundle_generated_at": base_bundle.get("generated_at", "unknown"),
        },
        "head": {
            "agent": head_manifest.get("name", "unknown"),
            "bundle_generated_at": head_bundle.get("generated_at", "unknown"),
        },
        "changes": {
            "sources": source_changes,
            "tools": tool_changes,
            "capabilities": capability_changes,
            "paths": path_changes,
        },
        "signals": signals,
        "summary": {
            "added_sources": len(source_changes["added"]),
            "removed_sources": len(source_changes["removed"]),
            "changed_sources": len(source_changes["changed"]),
            "added_tools": len(tool_changes["added"]),
            "removed_tools": len(tool_changes["removed"]),
            "changed_tools": len(tool_changes["changed"]),
            "tools_with_capability_changes": len(capability_changes),
            "added_capabilities": sum(len(change["added"]) for change in capability_changes),
            "removed_capabilities": sum(len(change["removed"]) for change in capability_changes),
            "added_paths": len(path_changes["added"]),
            "removed_paths": len(path_changes["removed"]),
            "decision_changes": len(path_changes["decision_changed"]),
            "review_signals": len(signals),
        },
        "limits": [
            (
                "The diff compares declared bundle content only; it does not discover runtime "
                "behavior or validate an external deployment."
            ),
            (
                "Review signals identify policy-relevant changes and require human judgment; "
                "they are not vulnerability findings or a security verdict."
            ),
        ],
    }
    return add_generated_at(diff, generated_at)
