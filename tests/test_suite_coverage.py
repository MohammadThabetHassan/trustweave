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
from suite_coverage import (  # noqa: E402
    Observation,
    Reading,
    load_adapter,
    measure,
    render,
)

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

    folded = cedar.fold_extra([cedar.read(path, "t.json")])["policies_1.cedar"]

    assert folded["request_cells_witnessed"] == 2
    assert folded["request_cells_witnessing_both_decisions"] == 1


def test_cedar_discover_ignores_json_that_is_not_a_suite(tmp_path: Path) -> None:
    """Entity stores and compiled policies are JSON too.

    They are not suites the adapter failed to read, so counting them would understate
    extraction against a denominator of files that were never tests.
    """

    _cedar_suite(tmp_path, [_request("allow")])
    (tmp_path / "entities.json").write_text(json.dumps([{"uid": "x"}]), encoding="utf-8")

    assert [path.name for path in cedar.discover(tmp_path)] == ["t.json"]


# ---------------------------------------------------------------------------------------
# Per-file supplementary data must survive subjects unifying across files
# ---------------------------------------------------------------------------------------


def test_cedar_unions_request_cells_across_suites_sharing_a_policy_set(tmp_path: Path) -> None:
    """Two suites may exercise one policy set; the cell counts are over their union.

    The Cedar corpus contains exactly this, so a per-file count keyed by policy set would
    report whichever file was read last.
    """

    first = cedar.read(_cedar_suite(tmp_path, [_request("allow", "view")], "a.json"), "a.json")
    second = cedar.read(_cedar_suite(tmp_path, [_request("deny", "edit")], "b.json"), "b.json")

    folded = cedar.fold_extra([first, second])["policies_1.cedar"]

    assert folded["request_cells_witnessed"] == 2
    assert sorted(folded["cells"]) == ["User|edit|Photo", "User|view|Photo"]


def test_cedar_folds_both_decisions_for_a_cell_split_across_suites(tmp_path: Path) -> None:
    first = cedar.read(_cedar_suite(tmp_path, [_request("allow", "view")], "a.json"), "a.json")
    second = cedar.read(_cedar_suite(tmp_path, [_request("deny", "view")], "b.json"), "b.json")

    folded = cedar.fold_extra([first, second])["policies_1.cedar"]

    assert folded["request_cells_witnessing_both_decisions"] == 1


def test_colliding_extras_are_refused_when_an_adapter_cannot_combine_them(
    tmp_path: Path,
) -> None:
    """Silently keeping the last writer is the failure this replaced."""

    readings = {
        "a": Reading("a", [_observation("p", "allow")], extra={"p": {"n": 1}}),
        "b": Reading("b", [_observation("p", "deny")], extra={"p": {"n": 2}}),
    }

    with pytest.raises(ValueError, match="declares no fold_extra"):
        _measure(tmp_path, readings)


# ---------------------------------------------------------------------------------------
# Refusal paths. The study's honesty rests on these naming what they could not read.
# ---------------------------------------------------------------------------------------


def test_rego_a_file_that_does_not_parse_is_named_not_silently_dropped(monkeypatch) -> None:
    monkeypatch.setattr(rego, "_parse", lambda path: None)

    assert rego.read(Path("a_test.rego"), "a_test.rego").not_extracted == (
        "does not parse as Rego v1 or v0"
    )


def test_rego_a_suite_with_no_test_rules_says_so(monkeypatch) -> None:
    monkeypatch.setattr(rego, "_parse", lambda path: {"rules": []})
    monkeypatch.setattr(rego, "builtins", frozenset)

    assert rego.read(Path("a_test.rego"), "a_test.rego").not_extracted == "no test rules"


def test_rego_a_suite_whose_tests_pin_nothing_reports_how_many_it_had(monkeypatch) -> None:
    """The distinction that matters: tests exist but the adapter could not read them."""

    ast = {"rules": [{"head": {"name": "test_a"}, "body": []}]}
    monkeypatch.setattr(rego, "_parse", lambda path: ast)
    monkeypatch.setattr(rego, "builtins", frozenset)

    assert rego.read(Path("a"), "a").not_extracted == "1 test rules, no decision pinned"


def test_kyverno_unreadable_yaml_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "kyverno-test.yaml"
    path.write_text("results: [\n  - policy: p\n   bad indent\n", encoding="utf-8")

    assert kyverno.read(path, "t.yaml").not_extracted == "not readable as YAML"


def test_kyverno_a_document_that_is_not_a_test_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "kyverno-test.yaml"
    path.write_text("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n", encoding="utf-8")

    assert kyverno.read(path, "t.yaml").not_extracted == "no cli.kyverno.io Test document"


def test_kyverno_results_without_a_labelled_outcome_are_counted_and_reported(
    tmp_path: Path,
) -> None:
    _cluster_policy(tmp_path, "r")
    path = _kyverno_test(tmp_path, "- policy: p\n  rule: r\n  kind: Pod\n")

    assert kyverno.read(path, "t.yaml").not_extracted == "1 results, none labelled"


def test_cedar_unreadable_json_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text("{not json", encoding="utf-8")

    assert cedar.read(path, "t.json").not_extracted == "not readable as JSON"


def test_cedar_a_document_without_requests_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"policies": "p.cedar"}), encoding="utf-8")

    assert cedar.read(path, "t.json").not_extracted == "no requests block"


def test_cedar_requests_without_a_decision_are_counted_and_reported(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text(
        json.dumps({"policies": "p.cedar", "requests": [{"principal": {"type": "User"}}]}),
        encoding="utf-8",
    )

    assert cedar.read(path, "t.json").not_extracted == "1 requests, none with a decision"


def test_a_single_file_target_is_read_without_a_directory_walk(tmp_path: Path) -> None:
    path = _cedar_suite(tmp_path, [_request("allow")])

    assert cedar.discover(path) == [path]


# ---------------------------------------------------------------------------------------
# Provenance and adapter loading
# ---------------------------------------------------------------------------------------


def test_provenance_of_a_directory_that_is_not_a_checkout_is_empty(tmp_path: Path) -> None:
    """A corpus with no git metadata yields no commits rather than invented ones."""

    from suite_coverage import provenance

    assert provenance(tmp_path) == []


def test_every_declared_adapter_satisfies_the_protocol() -> None:
    from suite_coverage import ADAPTER_MODULES, load_adapter

    for name in ADAPTER_MODULES:
        adapter = load_adapter(name)

        assert name == adapter.NAME
        assert adapter.DECISION_DOMAINS
        assert callable(adapter.discover) and callable(adapter.read)


# ---------------------------------------------------------------------------------------
# The opa invocation, stubbed. The v0 fallback is load-bearing for the corpus study.
# ---------------------------------------------------------------------------------------


class _Completed:
    def __init__(self, returncode: int, stdout: str) -> None:
        self.returncode = returncode
        self.stdout = stdout


def _stub_opa(monkeypatch, responses: list[_Completed]) -> list[list[str]]:
    calls: list[list[str]] = []

    def run(arguments, **kwargs):
        calls.append(arguments)
        return responses[len(calls) - 1]

    monkeypatch.setattr(rego, "_opa", lambda: "opa")
    monkeypatch.setattr(rego.subprocess, "run", run)
    return calls


def test_a_v0_suite_is_retried_rather_than_dropped(monkeypatch) -> None:
    """OPA 1.x parses v1 by default and most published suites are still v0."""

    calls = _stub_opa(monkeypatch, [_Completed(1, ""), _Completed(0, '{"rules": []}')])

    assert rego._parse(Path("a_test.rego")) == {"rules": []}
    assert len(calls) == 2
    assert "--v0-compatible" in calls[1]


def test_a_suite_parsing_as_v1_is_not_retried(monkeypatch) -> None:
    calls = _stub_opa(monkeypatch, [_Completed(0, '{"rules": []}')])

    rego._parse(Path("a_test.rego"))

    assert len(calls) == 1


def test_a_file_failing_both_parses_yields_nothing(monkeypatch) -> None:
    _stub_opa(monkeypatch, [_Completed(1, ""), _Completed(1, "")])

    assert rego._parse(Path("a_test.rego")) is None


def test_output_that_is_not_json_is_refused(monkeypatch) -> None:
    _stub_opa(monkeypatch, [_Completed(0, "not json"), _Completed(0, "not json")])

    assert rego._parse(Path("a_test.rego")) is None


def test_output_that_is_json_but_not_a_document_is_refused(monkeypatch) -> None:
    _stub_opa(monkeypatch, [_Completed(0, "[1, 2]"), _Completed(0, "[1, 2]")])

    assert rego._parse(Path("a_test.rego")) is None


def test_a_parse_that_cannot_be_run_is_refused(monkeypatch) -> None:
    monkeypatch.setattr(rego, "_opa", lambda: "opa")
    monkeypatch.setattr(rego.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError()))

    assert rego._parse(Path("a_test.rego")) is None


def test_builtins_are_taken_from_the_installed_opa(monkeypatch) -> None:
    """Hand-listing them would rot against the version actually installed."""

    monkeypatch.setattr(rego, "_BUILTINS", None)
    _stub_opa(monkeypatch, [_Completed(0, json.dumps({"builtins": [{"name": "trace"}]}))])

    assert "trace" in rego.builtins()


def test_an_unreadable_builtin_list_yields_an_empty_set_rather_than_a_guess(monkeypatch) -> None:
    monkeypatch.setattr(rego, "_BUILTINS", None)
    _stub_opa(monkeypatch, [_Completed(0, "not json")])

    assert rego.builtins() == frozenset()


def test_a_missing_opa_binary_is_reported_clearly(monkeypatch) -> None:
    monkeypatch.setattr(rego.shutil, "which", lambda name: None)

    with pytest.raises(SystemExit, match="opa is not on PATH"):
        rego._opa()


def test_the_rendered_summary_reports_each_domain_separately(tmp_path: Path) -> None:
    reading = Reading(
        "a",
        [
            _observation("p", "allow"),
            _observation("p", "deny"),
            Observation(domain="other", subject="q", decision="x", test="t"),
        ],
    )

    rendered = render(_measure(tmp_path, {"a": reading}))

    assert "policy subjects           2" in rendered
    assert "d " in rendered and "other " in rendered
    assert "witness >1" in rendered


def test_git_metadata_that_cannot_be_read_yields_no_provenance(monkeypatch, tmp_path: Path) -> None:
    """A corpus whose commit cannot be determined is reported without one, not with a guess."""

    import suite_coverage

    (tmp_path / ".git").mkdir()
    monkeypatch.setattr(
        suite_coverage.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError())
    )

    assert suite_coverage.provenance(tmp_path) == []


def test_the_documented_invocation_writes_the_artifact(tmp_path: Path) -> None:
    """`python scripts/suite_coverage.py cedar <corpus> --json out.json`, end to end."""

    import suite_coverage

    corpus = tmp_path / "corpus"
    corpus.mkdir()
    _cedar_suite(corpus, [_request("allow"), _request("deny")])
    out = tmp_path / "out.json"

    assert suite_coverage.main(["cedar", str(corpus), "--json", str(out)]) == 0

    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["ecosystem"] == "cedar"
    assert report["files_measured"] == 1
    assert report["subjects_blind"] == 0


# ---------------------------------------------------------------------------------------
# XACML adapter: the four-valued domain
# ---------------------------------------------------------------------------------------


def _xacml_suite(tmp_path: Path, responses: dict[str, str]) -> Path:
    suite = tmp_path / "basic" / "3"
    (suite / "responses").mkdir(parents=True, exist_ok=True)
    for name, decision in responses.items():
        (suite / "responses" / name).write_text(
            '<?xml version="1.0"?><Response><Result>'
            f"<Decision>{decision}</Decision></Result></Response>",
            encoding="utf-8",
        )
    return tmp_path


def test_xacml_cases_for_one_policy_unify_into_one_subject(tmp_path: Path) -> None:
    """`response_0001_01` and `response_0001_02` exercise the same policy."""

    root = _xacml_suite(
        tmp_path, {"response_0001_01.xml": "Permit", "response_0001_02.xml": "Deny"}
    )

    report = measure(load_adapter("xacml"), [root])

    assert report["subjects_measured"] == 1
    assert report["subjects"][0]["decisions_witnessed"] == ["Deny", "Permit"]


def test_xacml_separates_policies_by_their_index(tmp_path: Path) -> None:
    root = _xacml_suite(
        tmp_path, {"response_0001_01.xml": "Permit", "response_0002_01.xml": "Deny"}
    )

    assert measure(load_adapter("xacml"), [root])["subjects_measured"] == 2


def test_a_four_valued_domain_is_not_covered_by_testing_two_outcomes(tmp_path: Path) -> None:
    """The point of XACML here: `blind` is cleared by two outcomes, `covers_domain` is not."""

    root = _xacml_suite(
        tmp_path, {"response_0001_01.xml": "Permit", "response_0001_02.xml": "Deny"}
    )

    row = measure(load_adapter("xacml"), [root])["subjects"][0]

    assert row["blind"] is False
    assert row["covers_domain"] is False
    assert row["decisions_unwitnessed"] == ["Indeterminate", "NotApplicable"]


def test_witnessing_every_decision_covers_the_domain(tmp_path: Path) -> None:
    root = _xacml_suite(
        tmp_path,
        {
            "response_0001_01.xml": "Permit",
            "response_0001_02.xml": "Deny",
            "response_0001_03.xml": "NotApplicable",
            "response_0001_04.xml": "Indeterminate",
        },
    )

    assert measure(load_adapter("xacml"), [root])["subjects"][0]["covers_domain"] is True


def test_single_case_conformance_directories_are_not_measured(tmp_path: Path) -> None:
    """One case per language feature is a PDP conformance suite, not a policy test suite.

    Scoring those as decision-blind would be a category error rather than a finding.
    """

    case = tmp_path / "conformance" / "IIA001"
    case.mkdir(parents=True)
    (case / "policy.xml").write_text("<Policy/>", encoding="utf-8")
    (case / "response.xml").write_text(
        "<Response><Result><Decision>Permit</Decision></Result></Response>", encoding="utf-8"
    )

    assert load_adapter("xacml").discover(tmp_path) == []


def test_a_response_without_a_decision_is_named_rather_than_counted(tmp_path: Path) -> None:
    suite = tmp_path / "basic" / "3" / "responses"
    suite.mkdir(parents=True)
    path = suite / "response_0001_01.xml"
    path.write_text("<Response><Result/></Response>", encoding="utf-8")

    import suite_coverage_xacml

    assert suite_coverage_xacml.read(path, "r.xml").not_extracted == "no Decision element"
