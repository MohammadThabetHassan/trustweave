"""Bounded static analysis of supplied declared trust-boundary chains."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from difflib import get_close_matches
from typing import Any

from trustweave.models import (
    DEFAULT_CLASSIFICATION_TAXONOMY,
    ValidationError,
    contains_control_characters,
    reject_unknown_fields,
)
from trustweave.provenance import add_generated_at

# The chain renderer writes the same kind of Markdown the report renderers do, so it
# neutralises interpolated values with the same helper rather than a second copy of it.
from trustweave.report import _cell
from trustweave.rules import finding_for_rule

CHAIN_MANIFEST_SCHEMA_VERSION = "trustweave.dev/chain-manifest/v1alpha1"
CHAIN_REVIEW_SCHEMA_VERSION = "trustweave.dev/chain-review/v1alpha1"
VALID_NODE_KINDS = frozenset({"source", "data", "tool", "sink", "sanitizer", "approval"})
VALID_ACTION_CLASSES = frozenset({"read", "write", "sensitive", "external"})
SENSITIVE_CLASSIFICATIONS = frozenset({"confidential", "restricted"})
MAX_CLASSIFICATION_TAXONOMY = 32


@dataclass(frozen=True)
class ChainNode:
    """One reviewer-declared node; no behavior is inferred from its identifier or description."""

    identifier: str
    kind: str
    trust: str | None
    classification: str | None
    action_class: str | None
    fail_closed: bool | None
    covers_classifications: tuple[str, ...]


@dataclass(frozen=True)
class _TraversalState:
    """Bounded local propagation state for one explicitly declared chain path."""

    node: str
    path: tuple[str, ...]
    classifications: frozenset[str]
    approved_classifications: frozenset[str]
    incomplete_sanitizers: tuple[tuple[str, tuple[str, ...]], ...]


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{path} must be a non-empty string")
    text = value.strip()
    if contains_control_characters(text):
        raise ValidationError(f"{path} must not contain control characters")
    return text


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{path} must be an object")
    return value


def _sequence(value: Any, path: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValidationError(f"{path} must be a list")
    return value


@dataclass(frozen=True)
class ChainVocabulary:
    """The classification vocabulary one declared graph is reviewed against."""

    taxonomy: tuple[str, ...]
    sensitive: frozenset[str]


def _declared_list(root: Mapping[str, Any], field: str) -> tuple[str, ...] | None:
    """Read one optional bounded classification list from a chain manifest root."""

    if field not in root:
        return None
    path = f"chain_manifest.{field}"
    values = _sequence(root[field], path)
    if not values:
        raise ValidationError(f"{path} must not be empty")
    if len(values) > MAX_CLASSIFICATION_TAXONOMY:
        raise ValidationError(f"{path} must contain at most {MAX_CLASSIFICATION_TAXONOMY} entries")
    declared = tuple(_text(value, path) for value in values)
    if len(set(declared)) != len(declared):
        raise ValidationError(f"{path} must not contain duplicate classifications")
    return declared


def _parse_vocabulary(root: Mapping[str, Any]) -> ChainVocabulary:
    """Resolve which declared classifications this graph treats as sensitive.

    The analyzer used to carry the pair {"confidential", "restricted"} as a module
    constant, so a site whose own vocabulary says "pii" or "regulated" could not make
    chain-check see its data as sensitive by any configuration at all: the review found
    nothing, exited 0 and said so in plain language. A graph may now declare the taxonomy
    it is written in, and which of those terms propagate. Both fields are optional, so
    every chain manifest written against v1alpha1 keeps its meaning.
    """

    taxonomy = _declared_list(root, "classification_taxonomy") or DEFAULT_CLASSIFICATION_TAXONOMY
    declared_sensitive = _declared_list(root, "sensitive_classifications")
    if declared_sensitive is None:
        sensitive = tuple(value for value in taxonomy if value in SENSITIVE_CLASSIFICATIONS)
        if not sensitive:
            # Guessing which term in an unfamiliar taxonomy is the sensitive one would be
            # inventing the finding or inventing the silence. Ask instead.
            raise ValidationError(
                "chain_manifest.classification_taxonomy declares no classification this "
                "review treats as sensitive; declare chain_manifest.sensitive_classifications"
            )
        return ChainVocabulary(taxonomy, frozenset(sensitive))
    unknown = sorted(set(declared_sensitive) - set(taxonomy))
    if unknown:
        raise ValidationError(
            "chain_manifest.sensitive_classifications must name classifications from "
            f"chain_manifest.classification_taxonomy: {', '.join(unknown)}"
        )
    return ChainVocabulary(taxonomy, frozenset(declared_sensitive))


def _check_declared_classification(
    value: str, path: str, vocabulary: ChainVocabulary, warnings: list[str]
) -> None:
    """Refuse a near miss of a declared classification and report an unrecognised one.

    Propagation compares exact strings, so "Restricted" against a taxonomy holding
    "restricted" propagates nothing: no finding, exit 0, and a report stating that no
    reviewer-facing findings were produced. This is the failure engine's near-miss guard
    was written to refuse on the policy path, and it is refused here for the same reason.
    A plainly different term is descriptive metadata the graph may simply not treat as
    sensitive, so it is reported as a warning rather than refused.
    """

    if value in vocabulary.taxonomy:
        return
    folded = {entry.casefold(): entry for entry in vocabulary.taxonomy}
    match = folded.get(value.casefold())
    if match is None:
        close = get_close_matches(value.casefold(), list(folded), n=1, cutoff=0.85)
        match = folded[close[0]] if close else None
    if match is not None:
        raise ValidationError(
            f"{path} declares a classification the review will not match: {value!r} looks "
            f"like {match!r}. Classification propagation compares exact strings, so this "
            "would silently propagate nothing. Correct the declaration, or name the value "
            "in chain_manifest.classification_taxonomy."
        )
    warnings.append(
        f"Declared classification {value!r} is not named in the chain manifest's "
        "classification taxonomy, so it propagates nothing. Add it to "
        "classification_taxonomy, and to sensitive_classifications if it should propagate."
    )


def _parse_chain_manifest(
    document: Mapping[str, Any],
) -> tuple[dict[str, ChainNode], dict[str, tuple[str, ...]], ChainVocabulary, tuple[str, ...]]:
    root = _mapping(document, "chain_manifest")
    reject_unknown_fields(
        root,
        {
            "schema_version",
            "name",
            "nodes",
            "edges",
            "classification_taxonomy",
            "sensitive_classifications",
        },
        "chain_manifest",
    )
    if root.get("schema_version") != CHAIN_MANIFEST_SCHEMA_VERSION:
        raise ValidationError(
            f"chain_manifest.schema_version must be {CHAIN_MANIFEST_SCHEMA_VERSION}"
        )
    _text(root.get("name"), "chain_manifest.name")
    vocabulary = _parse_vocabulary(root)
    warnings: list[str] = []
    nodes: dict[str, ChainNode] = {}
    for index, raw_node in enumerate(_sequence(root.get("nodes"), "chain_manifest.nodes")):
        path = f"chain_manifest.nodes[{index}]"
        node = _mapping(raw_node, path)
        reject_unknown_fields(
            node,
            {
                "id",
                "kind",
                "trust",
                "classification",
                "action_class",
                "fail_closed",
                "covers_classifications",
            },
            path,
        )
        identifier = _text(node.get("id"), f"{path}.id")
        if identifier in nodes:
            raise ValidationError(f"chain_manifest.nodes contains duplicate id: {identifier}")
        kind = _text(node.get("kind"), f"{path}.kind")
        if kind not in VALID_NODE_KINDS:
            raise ValidationError(f"{path}.kind must be one of {sorted(VALID_NODE_KINDS)}")
        allowed_fields_by_kind = {
            "source": {"id", "kind", "trust", "classification"},
            "data": {"id", "kind", "classification"},
            "tool": {"id", "kind", "action_class"},
            "sink": {"id", "kind", "action_class"},
            "approval": {"id", "kind", "fail_closed"},
            "sanitizer": {"id", "kind", "covers_classifications"},
        }
        for field in sorted(set(node) - allowed_fields_by_kind[kind]):
            raise ValidationError(f"{path}.{field} is not valid for {kind} nodes")
        trust = node.get("trust")
        if trust is not None and trust not in {"trusted", "untrusted", "conditional"}:
            raise ValidationError(f"{path}.trust must be a declared trust label")
        classification = node.get("classification")
        if classification is not None:
            classification = _text(classification, f"{path}.classification")
            _check_declared_classification(
                classification, f"{path}.classification", vocabulary, warnings
            )
        action_class = node.get("action_class")
        if action_class is not None and action_class not in VALID_ACTION_CLASSES:
            raise ValidationError(
                f"{path}.action_class must be one of {sorted(VALID_ACTION_CLASSES)}"
            )
        fail_closed = node.get("fail_closed")
        if fail_closed is not None and not isinstance(fail_closed, bool):
            raise ValidationError(f"{path}.fail_closed must be a boolean")
        covers = tuple(
            _text(value, f"{path}.covers_classifications")
            for value in _sequence(
                node.get("covers_classifications", []), f"{path}.covers_classifications"
            )
        )
        for value in covers:
            _check_declared_classification(
                value, f"{path}.covers_classifications", vocabulary, warnings
            )
        if kind == "source" and trust is None:
            raise ValidationError(f"{path}.trust is required for source nodes")
        if kind == "data" and classification is None:
            raise ValidationError(f"{path}.classification is required for data nodes")
        if kind in {"tool", "sink"} and action_class is None:
            raise ValidationError(f"{path}.action_class is required for {kind} nodes")
        if kind == "approval" and fail_closed is None:
            raise ValidationError(f"{path}.fail_closed is required for approval nodes")
        if kind == "sanitizer" and not covers:
            raise ValidationError(f"{path}.covers_classifications is required for sanitizer nodes")
        if len(set(covers)) != len(covers):
            raise ValidationError(
                f"{path}.covers_classifications must not contain duplicate classifications"
            )
        nodes[identifier] = ChainNode(
            identifier,
            kind,
            trust,
            classification,
            action_class,
            fail_closed,
            tuple(sorted(set(covers))),
        )
    if not nodes:
        raise ValidationError("chain_manifest.nodes must not be empty")
    edges: dict[str, set[str]] = defaultdict(set)
    for index, raw_edge in enumerate(_sequence(root.get("edges"), "chain_manifest.edges")):
        path = f"chain_manifest.edges[{index}]"
        edge = _mapping(raw_edge, path)
        reject_unknown_fields(edge, {"from", "to"}, path)
        origin = _text(edge.get("from"), f"{path}.from")
        target = _text(edge.get("to"), f"{path}.to")
        if origin not in nodes or target not in nodes:
            raise ValidationError(f"{path} references an unknown declared node")
        edges[origin].add(target)
    return (
        nodes,
        {node: tuple(sorted(targets)) for node, targets in edges.items()},
        vocabulary,
        tuple(sorted(set(warnings))),
    )


def _finding(
    identifier: str,
    severity: str,
    message: str,
    path: tuple[str, ...],
    *,
    subject_extras: Mapping[str, Any] | None = None,
    **properties: Any,
) -> dict[str, Any]:
    """Build a bounded canonical finding for a supplied declared chain path.

    Whatever tells two findings on one path apart belongs in the subject, not only in
    `properties`. The risk fingerprint is built from (evidence kind, id, subject) and
    `risk.normalize_findings` drops `properties` entirely, so two incomplete sanitizers on
    one path were one risk identity: baselining either baselined both, with nothing recorded
    as dropped.
    """

    return finding_for_rule(
        identifier,
        severity,
        message,
        subject={"path": path, **(subject_extras or {})},
        location={"path_identity": " -> ".join(path) or "analysis_budget"},
        properties=properties,
    )


def _advance_state(
    state: _TraversalState, node: ChainNode, sensitive: frozenset[str]
) -> _TraversalState:
    """Apply the next declared node's static contract to a local traversal state."""

    classifications = state.classifications
    approved_classifications = state.approved_classifications
    incomplete_sanitizers = state.incomplete_sanitizers
    if node.classification in sensitive:
        classifications = classifications | {node.classification}
    if node.kind == "approval" and node.fail_closed is True and classifications:
        approved_classifications = classifications
    if node.kind == "sanitizer" and classifications:
        missing = tuple(sorted(classifications - set(node.covers_classifications)))
        if missing:
            incomplete_sanitizers = (*incomplete_sanitizers, (node.identifier, missing))
        covered = set(node.covers_classifications)
        classifications = classifications - covered
        approved_classifications = approved_classifications - covered
    return _TraversalState(
        node=state.node,
        path=state.path,
        classifications=frozenset(classifications),
        approved_classifications=frozenset(approved_classifications),
        incomplete_sanitizers=incomplete_sanitizers,
    )


def review_declared_chains(
    document: Mapping[str, Any],
    generated_at: str | None = None,
    *,
    max_nodes: int = 1000,
    max_paths: int = 1000,
    max_edges: int = 5000,
    max_depth: int = 100,
    max_states: int = 5000,
) -> dict[str, Any]:
    """Review declared paths with deterministic, bounded propagation of local static metadata."""

    budgets: dict[str, Any] = {
        "max_nodes": max_nodes,
        "max_paths": max_paths,
        "max_edges": max_edges,
        "max_depth": max_depth,
        "max_states": max_states,
    }
    if any(value < 1 for value in budgets.values()):
        raise ValidationError("chain analysis budgets must be positive")
    nodes, edges, vocabulary, warnings = _parse_chain_manifest(document)
    findings: list[dict[str, Any]] = []
    terminals: dict[tuple[str, ...], _TraversalState] = {}
    budget_name: str | None = "max_nodes" if len(nodes) > max_nodes else None
    depth_truncated = False
    edges_traversed = 0
    states_explored = 0
    if budget_name is None:
        starts = sorted(node.identifier for node in nodes.values() if node.trust == "untrusted")
        stack: list[_TraversalState] = [
            _TraversalState(start, (start,), frozenset(), frozenset(), ())
            for start in reversed(starts)
        ]
        seen_states: set[
            tuple[
                str,
                tuple[str, ...],
                frozenset[str],
                frozenset[str],
                tuple[tuple[str, tuple[str, ...]], ...],
            ]
        ] = set()
        while stack and budget_name is None:
            state = stack.pop()
            node = nodes[state.node]
            state = _advance_state(state, node, vocabulary.sensitive)
            identity = (
                state.node,
                state.path,
                state.classifications,
                state.approved_classifications,
                state.incomplete_sanitizers,
            )
            if identity in seen_states:
                continue
            if states_explored >= max_states:
                budget_name = "max_states"
                break
            seen_states.add(identity)
            states_explored += 1
            if node.action_class == "external":
                if state.path not in terminals and len(terminals) >= max_paths:
                    budget_name = "max_paths"
                    break
                terminals[state.path] = state
            # An external node is an output boundary, not the end of the declared graph:
            # the product's own discovery catalog classifies data-returning fetches as
            # external, so refusing to walk out of one hid every classification the call
            # brings back. The path is recorded as a terminal here and the walk continues.
            # A successor already on this path would only re-enumerate a cycle, so the
            # simple-path guard below is what keeps the traversal finite now that the
            # external stop no longer does it.
            successors = tuple(
                target for target in edges.get(state.node, ()) if target not in state.path
            )
            if not successors:
                continue
            if len(state.path) >= max_depth:
                # max_depth bounds one declared path, not the search. Assigning the
                # function-scoped budget here ended the whole traversal, so a single
                # reachable cycle discarded every unexplored sibling and suppressed the
                # findings of every untrusted source sorting after the cyclic one.
                depth_truncated = True
                continue
            for target in reversed(successors):
                if edges_traversed >= max_edges:
                    budget_name = "max_edges"
                    break
                edges_traversed += 1
                stack.append(
                    _TraversalState(
                        target,
                        state.path + (target,),
                        state.classifications,
                        state.approved_classifications,
                        state.incomplete_sanitizers,
                    )
                )

    for path, state in sorted(terminals.items()):
        classifications = sorted(state.classifications)
        if not classifications:
            continue
        findings.append(
            _finding(
                "TW-CHAIN-001",
                "high",
                (
                    "An explicitly declared untrusted path reaches sensitive data and an "
                    "external action."
                ),
                path,
                subject_extras={"classifications": classifications},
                classifications=classifications,
            )
        )
        unapproved = sorted(set(classifications) - set(state.approved_classifications))
        if unapproved:
            findings.append(
                _finding(
                    "TW-CHAIN-002",
                    "high",
                    (
                        "The declared sensitive-data path reaches an external action without a "
                        "declared fail-closed approval boundary."
                    ),
                    path,
                    subject_extras={"classifications": unapproved},
                    classifications=unapproved,
                )
            )
        for sanitizer, missing in state.incomplete_sanitizers:
            findings.append(
                _finding(
                    "TW-CHAIN-003",
                    "medium",
                    (
                        "A declared sanitizer does not list coverage for every propagated "
                        "sensitive classification."
                    ),
                    path,
                    subject_extras={"sanitizer": sanitizer},
                    classifications=list(missing),
                    sanitizer=sanitizer,
                )
            )
    if budget_name is not None or depth_truncated:
        findings.append(
            _finding(
                "TW-CHAIN-004",
                "medium",
                "The declared graph analysis budget was exceeded; the local review is incomplete.",
                (),
                budget=budget_name or "max_depth",
                **budgets,
            )
        )
    paths = sorted(terminals)
    review: dict[str, Any] = {
        "schema_version": CHAIN_REVIEW_SCHEMA_VERSION,
        "findings": findings,
        "warnings": list(warnings),
        "paths": [{"identity": list(path)} for path in paths],
        "summary": {
            "declared_nodes": len(nodes),
            "review_findings": len(findings),
            "paths": len(paths),
            "edges_traversed": edges_traversed,
            "states_explored": states_explored,
        },
        "limits": [
            (
                "Chain findings reflect only supplied declared nodes, edges, and bounded static "
                "metadata propagation. They do not prove a runtime data path, tool behavior, "
                "vulnerability, or deployed control state."
            )
        ],
    }
    return add_generated_at(review, generated_at)


def _analysis_was_truncated(findings: Sequence[Any]) -> bool:
    """True when a traversal budget stopped the search before it finished."""

    return any(_mapping(finding, "finding").get("id") == "TW-CHAIN-004" for finding in findings)


def render_chain_review(review: Mapping[str, Any]) -> str:
    """Render a bounded local chain-review summary without adding external evidence."""

    paths = _sequence(review.get("paths"), "chain_review.paths")
    findings = _sequence(review.get("findings"), "chain_review.findings")
    warnings = _sequence(review.get("warnings", []), "chain_review.warnings")
    truncated = _analysis_was_truncated(findings)
    lines = ["# Declared Chain Review", "", "## Declared paths", ""]
    if paths:
        lines.extend(
            "- `"
            + " -> ".join(
                _cell(node)
                for node in _sequence(_mapping(path, "path").get("identity"), "path.identity")
            )
            + "`"
            for path in paths
        )
    if truncated:
        # The traversal stopped at a budget, so part of the graph was never walked. The
        # caveat used to sit behind an else reachable only when no path was found at all,
        # which left a truncated run printing a path list that read as the whole answer.
        lines.append(
            "- Analysis incomplete: a traversal budget was reached before the declared graph "
            "was fully explored, so paths may exist that were not examined."
        )
    elif not paths:
        lines.append(
            "- No path from an explicitly declared untrusted source reached an external action."
        )
    lines.extend(["", "## Warnings", ""])
    if warnings:
        lines.extend(f"- {_cell(warning)}" for warning in warnings)
    else:
        lines.append("- Every declared classification was named in the classification taxonomy.")
    lines.extend(["", "## Review findings", ""])
    if findings:
        lines.extend(
            f"- **{_cell(_mapping(finding, 'finding').get('id'))}** "
            f"({_cell(_mapping(finding, 'finding').get('severity'))}): "
            f"{_cell(_mapping(finding, 'finding').get('message'))}"
            for finding in findings
        )
    else:
        lines.append("- No reviewer-facing findings were produced from the supplied declarations.")
    lines.extend(
        [
            "",
            "> This report reviews supplied declared graph metadata only. It does not demonstrate "
            "a runtime path, exploitability, or deployed control behavior.",
            "",
        ]
    )
    return "\n".join(lines)
