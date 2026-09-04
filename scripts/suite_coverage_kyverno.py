"""Read what a Kyverno CLI test manifest pins.

Kyverno is the useful case for this measure. A Gatekeeper constraint decides over two
values, and two values get covered in practice; Kyverno labels every expected result
`pass`, `fail` or `skip` against a named policy rule, so the suite states its expectation
directly rather than through an idiom. Extraction is consequently near total, which is the
condition under which the resulting number describes the suites rather than the adapter.

Rule type is resolved rather than assumed. A validate rule has a genuine pass/fail duality:
a resource either violates it or does not, so a suite that never witnesses a failure cannot
detect the rule silently ceasing to fire. A mutate or generate rule is tested by comparing
against a patched or generated resource, where `pass` means the patch matched and `fail` is
not an outcome the suite is expected to produce. Counting those together would report
mutation tests as blind and badly overstate the finding, so each rule type is reported in
its own decision domain.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from suite_coverage import Observation, Reading

NAME = "kyverno"
# The values the Kyverno CLI admits for an expected result. `skip` means the rule did not
# apply to the resource, which is a third outcome rather than a shade of the other two.
_RESULTS = ["fail", "pass", "skip"]
DECISION_DOMAINS = {
    "kyverno_validate": list(_RESULTS),
    "kyverno_mutate": list(_RESULTS),
    "kyverno_generate": list(_RESULTS),
    "kyverno_verifyImages": list(_RESULTS),
    "kyverno_delete": list(_RESULTS),
    # The referenced policy could not be resolved, so the rule's type is unknown and its
    # coverage must not be pooled with rules whose duality is known.
    "kyverno_unresolved": list(_RESULTS),
}

TEST_KIND = "Test"
RULE_TYPES = ("validate", "mutate", "generate", "verifyImages")

# Kyverno's newer CRDs state the rule type in the resource kind itself and carry no
# `spec.rules`, so the type is read from `kind` rather than from a rule body.
POLICY_KIND_TYPES = {
    "ValidatingPolicy": "validate",
    "ImageValidatingPolicy": "verifyImages",
    "MutatingPolicy": "mutate",
    "GeneratingPolicy": "generate",
    "DeletingPolicy": "delete",
}

# Kyverno synthesises Pod-controller variants of a rule. They are not written by hand and
# do not appear in the policy, but they inherit the type of the rule they are derived from.
AUTOGEN_PREFIXES = ("autogen-cronjob-", "autogen-")

_POLICY_CACHE: dict[Path, dict[str, Any] | None] = {}


def discover(root: Path) -> list[Path]:
    if not root.is_dir():
        return [root]
    return sorted(root.rglob("kyverno-test.yaml"))


def _load_yaml(path: Path) -> list[Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    try:
        return [document for document in yaml.safe_load_all(text) if document is not None]
    except yaml.YAMLError:
        return []


def _policy_documents(path: Path) -> dict[str, Any] | None:
    if path not in _POLICY_CACHE:
        documents = [document for document in _load_yaml(path) if isinstance(document, dict)]
        _POLICY_CACHE[path] = {"documents": documents} if documents else None
    return _POLICY_CACHE[path]


def _rule_types(test_path: Path, references: Any) -> dict[str, str]:
    """Map `policy/rule` to the kind of rule it is, by reading the referenced policies.

    Also records `policy/*` for a policy-level expectation, using the single rule type the
    policy uses, or `unresolved` when it mixes types and the entry names no rule.
    """

    kinds: dict[str, str] = {}
    if not isinstance(references, list):
        return kinds
    for reference in references:
        if not isinstance(reference, str):
            continue
        resolved = Path(os.path.normpath(test_path.parent / reference))
        loaded = _policy_documents(resolved)
        if loaded is None:
            continue
        for document in loaded["documents"]:
            name = (document.get("metadata") or {}).get("name")
            if not isinstance(name, str):
                continue
            declared = POLICY_KIND_TYPES.get(str(document.get("kind")))
            if declared is not None:
                kinds[f"{name}/*"] = declared
                continue
            seen: set[str] = set()
            for rule in (document.get("spec") or {}).get("rules") or []:
                if not isinstance(rule, dict):
                    continue
                kind = next((k for k in RULE_TYPES if k in rule), None)
                if kind is None:
                    continue
                seen.add(kind)
                if isinstance(rule.get("name"), str):
                    kinds[f"{name}/{rule['name']}"] = kind
            if len(seen) == 1:
                kinds[f"{name}/*"] = next(iter(seen))
    return kinds


def _autogen_kind(kinds: dict[str, str], policy: str, rule: Any) -> str | None:
    """Resolve a synthesised `autogen-` rule to the type of the rule it derives from."""

    if not isinstance(rule, str):
        return None
    for prefix in AUTOGEN_PREFIXES:
        if rule.startswith(prefix):
            return kinds.get(f"{policy}/{rule[len(prefix) :]}")
    return None


def read(path: Path, relative: str) -> Reading:
    documents = _load_yaml(path)
    if not documents:
        return Reading(path=relative, not_extracted="not readable as YAML")

    tests = [
        document
        for document in documents
        if isinstance(document, dict) and document.get("kind") == TEST_KIND
    ]
    if not tests:
        return Reading(path=relative, not_extracted="no cli.kyverno.io Test document")

    observations: list[Observation] = []
    entries = 0
    for document in tests:
        name = str((document.get("metadata") or {}).get("name") or relative)
        kinds = _rule_types(path, document.get("policies"))
        results = document.get("results")
        for entry in results if isinstance(results, list) else []:
            if not isinstance(entry, dict):
                continue
            entries += 1
            policy = entry.get("policy")
            rule = entry.get("rule")
            decision = entry.get("result")
            if not isinstance(decision, str) or not isinstance(policy, str):
                continue
            # A mutate or generate test may declare a policy-level expectation with no rule.
            # Naming that subject `policy/*` keeps it distinct from a named rule of the same
            # policy rather than silently merging the two.
            subject = f"{policy}/{rule}" if isinstance(rule, str) else f"{policy}/*"
            kind = kinds.get(subject) or _autogen_kind(kinds, policy, rule) or "unresolved"
            observations.append(
                Observation(
                    domain=f"kyverno_{kind}",
                    subject=subject,
                    decision=decision,
                    test=name,
                )
            )

    if not observations:
        reason = "no results block" if entries == 0 else f"{entries} results, none labelled"
        return Reading(path=relative, not_extracted=reason)
    return Reading(path=relative, observations=observations)
