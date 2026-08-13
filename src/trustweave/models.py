"""Typed models and validation for TrustWeave's declarative agent manifest."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from difflib import get_close_matches
from typing import Any


class ValidationError(ValueError):
    """Raised when a TrustWeave data contract fails validation."""


class InputOutputError(OSError):
    """Raised when a local evidence input or output cannot be safely accessed."""


@dataclass(frozen=True)
class Source:
    """A named ingress point for data or instructions."""

    name: str
    trust: str
    data_classification: str
    description: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class Tool:
    """A declared action endpoint available to an agent."""

    name: str
    action_class: str
    capabilities: tuple[str, ...]
    description: str

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["capabilities"] = list(self.capabilities)
        return result


@dataclass(frozen=True)
class Flow:
    """A declared source-to-tool route subject to a deterministic policy."""

    source: str
    tool: str
    purpose: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class AgentManifest:
    """A validated declarative description of a bounded agent architecture."""

    schema_version: str
    name: str
    description: str
    sources: tuple[Source, ...]
    tools: tuple[Tool, ...]
    flows: tuple[Flow, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "description": self.description,
            "sources": [source.as_dict() for source in self.sources],
            "tools": [tool.as_dict() for tool in self.tools],
            "flows": [flow.as_dict() for flow in self.flows],
        }


@dataclass(frozen=True)
class PolicyRule:
    """A simple deterministic policy rule evaluated against a flow."""

    id: str
    description: str
    source_trust: tuple[str, ...]
    tool_action_classes: tuple[str, ...]
    decision: str
    rationale: str


@dataclass(frozen=True)
class ApprovalControl:
    """A declared design-time contract for high-impact human approval."""

    mechanism: str
    binds_to: tuple[str, ...]
    fail_closed: bool


@dataclass(frozen=True)
class Policy:
    """Validated deterministic flow-control policy."""

    schema_version: str
    name: str
    default_decision: str
    rules: tuple[PolicyRule, ...]
    approval_control: ApprovalControl | None


VALID_TRUST_LABELS = frozenset({"trusted", "untrusted", "conditional"})
VALID_ACTION_CLASSES = frozenset({"read", "write", "sensitive", "external"})
VALID_DECISIONS = frozenset({"allow", "deny", "require_approval"})


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{path} must be a non-empty string")
    return value.strip()


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{path} must be an object")
    return value


def _sequence(value: Any, path: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValidationError(f"{path} must be a list")
    return value


def reject_unknown_fields(value: Mapping[str, Any], allowed: set[str], path: str) -> None:
    for field in sorted(set(value) - allowed):
        suggestions = get_close_matches(field, sorted(allowed), n=1, cutoff=0.6)
        suggestion = f"; did you mean {suggestions[0]!r}?" if suggestions else ""
        raise ValidationError(f"{path}: unknown field {field!r}{suggestion}")


def _unique_names(items: Sequence[str], path: str) -> None:
    duplicates = sorted(item for item, count in Counter(items).items() if count > 1)
    if duplicates:
        raise ValidationError(f"{path} contains duplicate values: {', '.join(duplicates)}")


def parse_manifest(document: Mapping[str, Any]) -> AgentManifest:
    """Validate a manifest document and return its typed, immutable representation."""

    root = _mapping(document, "manifest")
    reject_unknown_fields(
        root,
        {"schema_version", "name", "description", "sources", "tools", "flows"},
        "manifest",
    )
    schema_version = _string(root.get("schema_version"), "manifest.schema_version")
    if schema_version != "trustweave.dev/v1alpha1":
        raise ValidationError("manifest.schema_version must be trustweave.dev/v1alpha1")

    sources: list[Source] = []
    for index, raw_source in enumerate(_sequence(root.get("sources"), "manifest.sources")):
        source = _mapping(raw_source, f"manifest.sources[{index}]")
        reject_unknown_fields(
            source,
            {"name", "trust", "data_classification", "description"},
            f"manifest.sources[{index}]",
        )
        trust = _string(source.get("trust"), f"manifest.sources[{index}].trust")
        if trust not in VALID_TRUST_LABELS:
            raise ValidationError(
                f"manifest.sources[{index}].trust must be one of {sorted(VALID_TRUST_LABELS)}"
            )
        sources.append(
            Source(
                name=_string(source.get("name"), f"manifest.sources[{index}].name"),
                trust=trust,
                data_classification=_string(
                    source.get("data_classification"),
                    f"manifest.sources[{index}].data_classification",
                ),
                description=_string(
                    source.get("description"), f"manifest.sources[{index}].description"
                ),
            )
        )
    if not sources:
        raise ValidationError("manifest.sources must contain at least one source")
    _unique_names([source.name for source in sources], "manifest.sources.name")

    tools: list[Tool] = []
    for index, raw_tool in enumerate(_sequence(root.get("tools"), "manifest.tools")):
        tool = _mapping(raw_tool, f"manifest.tools[{index}]")
        reject_unknown_fields(
            tool,
            {"name", "action_class", "capabilities", "description"},
            f"manifest.tools[{index}]",
        )
        action_class = _string(tool.get("action_class"), f"manifest.tools[{index}].action_class")
        if action_class not in VALID_ACTION_CLASSES:
            allowed_actions = sorted(VALID_ACTION_CLASSES)
            raise ValidationError(
                f"manifest.tools[{index}].action_class must be one of {allowed_actions}"
            )
        capabilities = tuple(
            _string(capability, f"manifest.tools[{index}].capabilities")
            for capability in _sequence(
                tool.get("capabilities"), f"manifest.tools[{index}].capabilities"
            )
        )
        if not capabilities:
            raise ValidationError(f"manifest.tools[{index}].capabilities must not be empty")
        _unique_names(list(capabilities), f"manifest.tools[{index}].capabilities")
        tools.append(
            Tool(
                name=_string(tool.get("name"), f"manifest.tools[{index}].name"),
                action_class=action_class,
                capabilities=capabilities,
                description=_string(
                    tool.get("description"), f"manifest.tools[{index}].description"
                ),
            )
        )
    if not tools:
        raise ValidationError("manifest.tools must contain at least one tool")
    _unique_names([tool.name for tool in tools], "manifest.tools.name")

    source_names = {source.name for source in sources}
    tool_names = {tool.name for tool in tools}
    flows: list[Flow] = []
    for index, raw_flow in enumerate(_sequence(root.get("flows"), "manifest.flows")):
        flow = _mapping(raw_flow, f"manifest.flows[{index}]")
        reject_unknown_fields(
            flow,
            {"source", "tool", "purpose"},
            f"manifest.flows[{index}]",
        )
        source_name = _string(flow.get("source"), f"manifest.flows[{index}].source")
        tool_name = _string(flow.get("tool"), f"manifest.flows[{index}].tool")
        if source_name not in source_names:
            raise ValidationError(
                f"manifest.flows[{index}].source references unknown source {source_name}"
            )
        if tool_name not in tool_names:
            raise ValidationError(
                f"manifest.flows[{index}].tool references unknown tool {tool_name}"
            )
        flows.append(
            Flow(
                source=source_name,
                tool=tool_name,
                purpose=_string(flow.get("purpose"), f"manifest.flows[{index}].purpose"),
            )
        )
    if not flows:
        raise ValidationError("manifest.flows must contain at least one flow")

    return AgentManifest(
        schema_version=schema_version,
        name=_string(root.get("name"), "manifest.name"),
        description=_string(root.get("description"), "manifest.description"),
        sources=tuple(sources),
        tools=tuple(tools),
        flows=tuple(flows),
    )


def parse_policy(document: Mapping[str, Any]) -> Policy:
    """Validate a policy document and return its typed, immutable representation."""

    root = _mapping(document, "policy")
    reject_unknown_fields(
        root,
        {"schema_version", "name", "default_decision", "rules", "approval_control"},
        "policy",
    )
    schema_version = _string(root.get("schema_version"), "policy.schema_version")
    if schema_version != "trustweave.dev/v1alpha1":
        raise ValidationError("policy.schema_version must be trustweave.dev/v1alpha1")
    default_decision = _string(root.get("default_decision"), "policy.default_decision")
    if default_decision not in VALID_DECISIONS:
        raise ValidationError(f"policy.default_decision must be one of {sorted(VALID_DECISIONS)}")

    rules: list[PolicyRule] = []
    for index, raw_rule in enumerate(_sequence(root.get("rules"), "policy.rules")):
        rule = _mapping(raw_rule, f"policy.rules[{index}]")
        reject_unknown_fields(
            rule,
            {"id", "description", "source_trust", "tool_action_classes", "decision", "rationale"},
            f"policy.rules[{index}]",
        )
        source_trust = tuple(
            _string(value, f"policy.rules[{index}].source_trust")
            for value in _sequence(rule.get("source_trust"), f"policy.rules[{index}].source_trust")
        )
        action_classes = tuple(
            _string(value, f"policy.rules[{index}].tool_action_classes")
            for value in _sequence(
                rule.get("tool_action_classes"),
                f"policy.rules[{index}].tool_action_classes",
            )
        )
        if not source_trust or not action_classes:
            raise ValidationError(
                f"policy.rules[{index}] requires source_trust and tool_action_classes"
            )
        unknown_trust = set(source_trust) - VALID_TRUST_LABELS
        unknown_actions = set(action_classes) - VALID_ACTION_CLASSES
        if unknown_trust:
            raise ValidationError(
                f"policy.rules[{index}] has unknown trust labels: {sorted(unknown_trust)}"
            )
        if unknown_actions:
            raise ValidationError(
                f"policy.rules[{index}] has unknown action classes: {sorted(unknown_actions)}"
            )
        decision = _string(rule.get("decision"), f"policy.rules[{index}].decision")
        if decision not in VALID_DECISIONS:
            raise ValidationError(
                f"policy.rules[{index}].decision must be one of {sorted(VALID_DECISIONS)}"
            )
        rules.append(
            PolicyRule(
                id=_string(rule.get("id"), f"policy.rules[{index}].id"),
                description=_string(rule.get("description"), f"policy.rules[{index}].description"),
                source_trust=source_trust,
                tool_action_classes=action_classes,
                decision=decision,
                rationale=_string(rule.get("rationale"), f"policy.rules[{index}].rationale"),
            )
        )
    _unique_names([rule.id for rule in rules], "policy.rules.id")

    approval_control: ApprovalControl | None = None
    if "approval_control" in root:
        control = _mapping(root["approval_control"], "policy.approval_control")
        reject_unknown_fields(
            control,
            {"mechanism", "binds_to", "fail_closed"},
            "policy.approval_control",
        )
        binds_to = tuple(
            _string(value, "policy.approval_control.binds_to")
            for value in _sequence(control.get("binds_to"), "policy.approval_control.binds_to")
        )
        if not binds_to:
            raise ValidationError("policy.approval_control.binds_to must not be empty")
        _unique_names(list(binds_to), "policy.approval_control.binds_to")
        fail_closed = control.get("fail_closed")
        if not isinstance(fail_closed, bool):
            raise ValidationError("policy.approval_control.fail_closed must be a boolean")
        approval_control = ApprovalControl(
            mechanism=_string(control.get("mechanism"), "policy.approval_control.mechanism"),
            binds_to=binds_to,
            fail_closed=fail_closed,
        )

    return Policy(
        schema_version=schema_version,
        name=_string(root.get("name"), "policy.name"),
        default_decision=default_decision,
        rules=tuple(rules),
        approval_control=approval_control,
    )
