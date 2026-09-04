"""The cross-ecosystem suite-coverage instrument and its three adapters.

The Rego adapter shells out to `opa parse` for an AST, so an end-to-end test would need opa
in CI. The part worth pinning is the reading of that AST, which is pure, so those tests hand
it the shapes opa actually emits, transcribed from real `opa parse --format json` output.
The Kyverno and Cedar adapters read files directly and are tested against written fixtures.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import suite_coverage_cedar as cedar  # noqa: E402
import suite_coverage_kyverno as kyverno  # noqa: E402
import suite_coverage_rego as rego  # noqa: E402
from suite_coverage import Observation, Reading, measure, render  # noqa: E402

# ---------------------------------------------------------------------------------------
# Core: folding observations into subjects
# ---------------------------------------------------------------------------------------


class _Adapter:
    NAME = "fake"
    DECISION_DOMAINS = {"d": ["allow", "deny"]}

    def __init__(self, readings: dict[str, Reading]) -> None:
        self._readings = readings

    def discover(self, root: Path) -> list[Path]:
        return [root / name for name in sorted(self._readings)]

    def read(self, path: Path, relative: str) -> Reading:
        return self._readings[path.name]


def _observation(subject: str, decision: str) -> Observation:
    return Observation(domain="d", subject=subject, decision=decision, test="t")


def _measure(tmp_path: Path, readings: dict[str, Reading]) -> dict[str, Any]:
    return measure(_Adapter(readings), [tmp_path])


def test_a_subject_witnessing_one_decision_is_blind(tmp_path: Path) -> None:
    report = _measure(tmp_path, {"a": Reading("a", [_observation("p", "allow")])})

    assert report["subjects_blind"] == 1
    assert report["subjects"][0]["decisions_unwitnessed"] == ["deny"]


def test_a_subject_witnessing_both_decisions_is_not_blind(tmp_path: Path) -> None:
    reading = Reading("a", [_observation("p", "allow"), _observation("p", "deny")])

    assert _measure(tmp_path, {"a": reading})["subjects_blind"] == 0


def test_observations_for_one_subject_unify_across_files(tmp_path: Path) -> None:
    """A rule exercised by two suites is blind only if neither witnesses a second decision."""

    report = _measure(
        tmp_path,
        {
            "a": Reading("a", [_observation("p", "allow")]),
            "b": Reading("b", [_observation("p", "deny")]),
        },
    )

    assert report["subjects_measured"] == 1
    assert report["subjects_blind"] == 0


def test_extraction_below_the_floor_suppresses_the_summary(tmp_path: Path) -> None:
    """A conclusion drawn from the files an adapter happens to read describes the adapter."""

    readings = {str(index): Reading(str(index), not_extracted="unreadable") for index in range(9)}
    readings["9"] = Reading("9", [_observation("p", "allow")])

    report = _measure(tmp_path, readings)

    assert report["extraction_rate"] == 0.1
    assert report["sufficient_for_summary"] is False
    assert "WARNING" in render(report)


def test_full_extraction_permits_the_summary(tmp_path: Path) -> None:
    report = _measure(tmp_path, {"a": Reading("a", [_observation("p", "allow")])})

    assert report["sufficient_for_summary"] is True
    assert "WARNING" not in render(report)


def test_files_yielding_nothing_are_named_with_a_reason(tmp_path: Path) -> None:
    report = _measure(
        tmp_path,
        {
            "a": Reading("a", [_observation("p", "allow")]),
            "b": Reading("b", not_extracted="commented out"),
        },
    )

    assert report["not_extracted"] == [{"file": "b", "reason": "commented out"}]


def test_domains_are_reported_separately(tmp_path: Path) -> None:
    """Pooling domains with different dualities would misreport one of them."""

    reading = Reading(
        "a",
        [
            _observation("p", "allow"),
            Observation(domain="other", subject="q", decision="x", test="t"),
        ],
    )

    assert set(_measure(tmp_path, {"a": reading})["by_domain"]) == {"d", "other"}


# ---------------------------------------------------------------------------------------
# Rego adapter
# ---------------------------------------------------------------------------------------


def _var(name: str) -> dict[str, Any]:
    return {"type": "var", "value": name}


def _ref(head: str, *rest: str) -> dict[str, Any]:
    return {"type": "ref", "value": [_var(head), *({"type": "string", "value": r} for r in rest)]}


def _call(function: str, argument: dict[str, Any]) -> dict[str, Any]:
    return {"type": "call", "value": [_ref(function), argument]}


def _number(value: int) -> dict[str, Any]:
    return {"type": "number", "value": value}


def _expression(terms: Any, negated: bool = False) -> dict[str, Any]:
    return {"terms": terms, "negated": negated}


def _suite(*body: dict[str, Any], extra: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {"rules": [{"head": {"name": "test_case"}, "body": list(body)}, *(extra or [])]}


BIND = _expression([_ref("assign"), _var("results"), _var("violation")])


def _decisions(ast: dict[str, Any], **kwargs: Any) -> list[str]:
    return [o.decision for o in rego.assertions(ast, **kwargs)]


def test_rego_iterating_a_bound_violation_set_pins_a_denial() -> None:
    assert _decisions(_suite(BIND, _expression(_ref("results", "result")))) == ["nonempty"]


def test_rego_negated_iteration_pins_a_permit() -> None:
    body = _expression(_ref("results", "_"), negated=True)

    assert _decisions(_suite(BIND, body)) == ["empty"]


@pytest.mark.parametrize(
    ("operator", "count", "expected"),
    [
        ("equal", 0, "empty"),
        ("equal", 1, "nonempty"),
        ("gt", 0, "nonempty"),
        ("gte", 1, "nonempty"),
        ("lt", 1, "empty"),
        ("lte", 0, "empty"),
        ("neq", 0, "nonempty"),
    ],
)
def test_rego_count_comparisons_resolve(operator: str, count: int, expected: str) -> None:
    body = _expression([_ref(operator), _call("count", _var("results")), _number(count)])

    assert _decisions(_suite(BIND, body)) == [expected]


def test_rego_a_reversed_comparison_reads_the_same() -> None:
    """`0 < count(results)` asserts exactly what `count(results) > 0` asserts."""

    body = _expression([_ref("lt"), _number(0), _call("count", _var("results"))])

    assert _decisions(_suite(BIND, body)) == ["nonempty"]


def test_rego_a_count_comparison_that_does_not_settle_emptiness_is_refused() -> None:
    body = _expression([_ref("neq"), _call("count", _var("results")), _number(2)])

    assert rego.assertions(_suite(BIND, body)) == []


def test_rego_an_unbound_local_is_not_read_as_a_decision() -> None:
    assert rego.assertions(_suite(_expression(_ref("results", "result")))) == []


def test_rego_reading_a_field_of_the_bound_set_witnesses_a_denial() -> None:
    """`results[_].msg == "x"` iterates the set, so it can only hold when one exists."""

    body = _expression([_ref("equal"), _ref("results", "msg"), {"type": "string", "value": "x"}])

    observations = rego.assertions(_suite(BIND, body))

    assert [o.decision for o in observations] == ["nonempty"]
    assert observations[0].domain == "violation_set"


def test_rego_comparing_against_a_constant_nonempty_rule_witnesses_a_denial() -> None:
    """`result == policy_violation`, where that rule always yields a member."""

    expected_rule = {
        "head": {"name": "policy_violation", "key": {"type": "string", "value": "m"}},
        "body": [_expression([_ref("assign"), _var("msg"), {"type": "string", "value": "m"}])],
    }
    bind = _expression([_ref("assign"), _var("result"), _var("violation")])
    body = _expression([_ref("equal"), _var("result"), _var("policy_violation")])

    assert _decisions(_suite(bind, body, extra=[expected_rule])) == ["nonempty"]


def test_rego_comparing_against_an_unresolvable_rule_is_refused() -> None:
    """Without a definition, the expected set could be empty; assuming otherwise invents one."""

    bind = _expression([_ref("assign"), _var("result"), _var("violation")])
    body = _expression([_ref("equal"), _var("result"), _var("something_unknown")])

    assert rego.assertions(_suite(bind, body)) == []


def test_rego_a_builtin_call_is_not_a_policy_subject() -> None:
    """`trace(...)` is a debug statement structurally identical to a helper invocation."""

    body = _expression([_ref("trace"), {"type": "string", "value": "x"}])

    assert rego.assertions(_suite(body), known_builtins=frozenset({"trace"})) == []


def test_rego_a_helper_rule_is_measured_in_the_boolean_domain() -> None:
    observations = rego.assertions(_suite(_expression([_ref("is_exempt"), _var("input")])))

    assert observations[0].domain == "boolean"
    assert observations[0].decision == "holds"


def test_rego_an_excluding_comparison_does_not_witness_a_decision() -> None:
    """`decision != "deny"` runs the line while leaving the value open."""

    body = _expression([_ref("neq"), _ref("authz", "decision"), {"type": "string", "value": "d"}])

    assert rego.assertions(_suite(body)) == []


def test_rego_only_test_rules_are_measured() -> None:
    assert rego.assertions({"rules": [{"head": {"name": "violation"}, "body": [BIND]}]}) == []


def test_rego_the_subject_is_scoped_to_its_file() -> None:
    """Rego rule names are package-local, so `violation` alone would merge every suite."""

    observations = rego.assertions(
        _suite(BIND, _expression(_ref("results", "r"))), scope="a/src_test.rego"
    )

    assert observations[0].subject == "a/src_test.rego::violation"


# ---------------------------------------------------------------------------------------
# Kyverno adapter
# ---------------------------------------------------------------------------------------


def _kyverno_test(tmp_path: Path, results: str, policy_file: str = "policy.yaml") -> Path:
    path = tmp_path / "kyverno-test.yaml"
    path.write_text(
        "apiVersion: cli.kyverno.io/v1alpha1\n"
        "kind: Test\n"
        "metadata:\n  name: t\n"
        f"policies:\n- {policy_file}\n"
        "resources:\n- resource.yaml\n"
        f"results:\n{results}",
        encoding="utf-8",
    )
    return path


def _cluster_policy(tmp_path: Path, rule: str, kind: str = "validate") -> None:
    (tmp_path / "policy.yaml").write_text(
        "apiVersion: kyverno.io/v1\n"
        "kind: ClusterPolicy\n"
        "metadata:\n  name: p\n"
        f"spec:\n  rules:\n  - name: {rule}\n    {kind}:\n      message: m\n",
        encoding="utf-8",
    )


def test_kyverno_reads_the_labelled_result_of_each_rule(tmp_path: Path) -> None:
    _cluster_policy(tmp_path, "r")
    path = _kyverno_test(
        tmp_path,
        "- policy: p\n  rule: r\n  kind: Pod\n  resources: [a]\n  result: pass\n"
        "- policy: p\n  rule: r\n  kind: Pod\n  resources: [b]\n  result: fail\n",
    )

    reading = kyverno.read(path, "kyverno-test.yaml")

    assert sorted(o.decision for o in reading.observations) == ["fail", "pass"]
    assert {o.subject for o in reading.observations} == {"p/r"}


def test_kyverno_reports_rule_type_as_the_domain(tmp_path: Path) -> None:
    """A mutate rule has no failure outcome, so pooling it with validate would mislead."""

    _cluster_policy(tmp_path, "r", kind="mutate")
    path = _kyverno_test(tmp_path, "- policy: p\n  rule: r\n  kind: Pod\n  result: pass\n")

    assert kyverno.read(path, "t.yaml").observations[0].domain == "kyverno_mutate"


def test_kyverno_resolves_a_newer_crd_from_its_kind(tmp_path: Path) -> None:
    """ValidatingPolicy carries no spec.rules; its type is the resource kind."""

    (tmp_path / "policy.yaml").write_text(
        "apiVersion: policies.kyverno.io/v1alpha1\nkind: ValidatingPolicy\nmetadata:\n  name: p\n",
        encoding="utf-8",
    )
    path = _kyverno_test(tmp_path, "- policy: p\n  kind: Pod\n  result: pass\n")

    observation = kyverno.read(path, "t.yaml").observations[0]

    assert (observation.domain, observation.subject) == ("kyverno_validate", "p/*")


def test_kyverno_resolves_a_synthesised_autogen_rule(tmp_path: Path) -> None:
    _cluster_policy(tmp_path, "r")
    path = _kyverno_test(tmp_path, "- policy: p\n  rule: autogen-cronjob-r\n  result: fail\n")

    assert kyverno.read(path, "t.yaml").observations[0].domain == "kyverno_validate"


def test_kyverno_an_unresolvable_policy_is_not_pooled_with_known_types(tmp_path: Path) -> None:
    path = _kyverno_test(tmp_path, "- policy: p\n  rule: r\n  result: pass\n", "missing.yaml")

    assert kyverno.read(path, "t.yaml").observations[0].domain == "kyverno_unresolved"


def test_kyverno_a_manifest_without_results_is_named_rather_than_counted(tmp_path: Path) -> None:
    path = tmp_path / "kyverno-test.yaml"
    path.write_text(
        "apiVersion: cli.kyverno.io/v1alpha1\nkind: Test\nmetadata:\n  name: t\npolicies: []\n",
        encoding="utf-8",
    )

    assert kyverno.read(path, "t.yaml").not_extracted == "no results block"


# ---------------------------------------------------------------------------------------
# Cedar adapter
# ---------------------------------------------------------------------------------------


def _cedar_suite(tmp_path: Path, requests: list[dict[str, Any]], name: str = "t.json") -> Path:
    path = tmp_path / name
    path.write_text(
        json.dumps({"policies": "policies_1.cedar", "requests": requests}), encoding="utf-8"
    )
    return path


def _request(decision: str, action: str = "view") -> dict[str, Any]:
    return {
        "principal": {"type": "User", "id": "alice"},
        "action": {"type": "Action", "id": action},
        "resource": {"type": "Photo", "id": "p"},
        "decision": decision,
    }


def test_cedar_reads_the_decision_of_each_request(tmp_path: Path) -> None:
    path = _cedar_suite(tmp_path, [_request("allow"), _request("deny")])

    reading = cedar.read(path, "t.json")

    assert sorted(o.decision for o in reading.observations) == ["allow", "deny"]
    assert {o.subject for o in reading.observations} == {"policies_1.cedar"}


def test_cedar_normalises_decision_case(tmp_path: Path) -> None:
    path = _cedar_suite(tmp_path, [_request("Allow")])

    assert cedar.read(path, "t.json").observations[0].decision == "allow"


def test_cedar_records_request_cells_witnessed_under_both_decisions(tmp_path: Path) -> None:
    path = _cedar_suite(
        tmp_path,
        [_request("allow", "view"), _request("deny", "view"), _request("allow", "edit")],
    )

    extra = cedar.read(path, "t.json").extra["policies_1.cedar"]

    assert extra["request_cells_witnessed"] == 2
    assert extra["request_cells_witnessing_both_decisions"] == 1


def test_cedar_discover_ignores_json_that_is_not_a_suite(tmp_path: Path) -> None:
    """Entity stores and compiled policies are JSON too.

    They are not suites the adapter failed to read, so counting them would understate
    extraction against a denominator of files that were never tests.
    """

    _cedar_suite(tmp_path, [_request("allow")])
    (tmp_path / "entities.json").write_text(json.dumps([{"uid": "x"}]), encoding="utf-8")

    assert [path.name for path in cedar.discover(tmp_path)] == ["t.json"]
