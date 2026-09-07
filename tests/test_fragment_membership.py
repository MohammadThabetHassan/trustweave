"""Tests for the cross-ecosystem fragment-membership instrument.

These measurements are the only evidence behind section 4b of
docs/DECISION_CLASS_COVERAGE.md, and behind the stratified reading of the Kyverno
association in docs/SUITE_COVERAGE_STUDY.md. The corpora are not in the repository -- they
are fetched at the commits the study pins -- so the cases that must not regress are
asserted here on transcribed policies and on the committed artifacts, and run without a
network.

Each adapter's dangerous failure is the same: reporting a verdict where it should refuse.
Every adapter therefore has an explicit case for an unrecognised construct.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
ECOSYSTEMS = ("xacml", "kyverno", "cedar")


def _load(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


core = _load("fragment_membership")
xacml = _load("fragment_membership_xacml")
kyverno = _load("fragment_membership_kyverno")
cedar = _load("fragment_membership_cedar")


class TestCore:
    def test_a_verdict_must_be_one_of_the_three(self) -> None:
        with pytest.raises(ValueError):
            core.Verdict("probably", "no")

    def test_subjects_are_read_from_a_suite_coverage_artifact(self) -> None:
        assert core.subjects_of({"subjects": [{"subject": "a"}, {"subject": "b"}]}) == {"a", "b"}

    def test_subjects_are_read_from_a_mutation_artifact(self) -> None:
        """The Kyverno join needs the mutation artifact's shape, not the coverage one."""

        assert core.subjects_of({"detail": [{"policy": "p"}, {"policy": "q"}]}) == {"p", "q"}

    def test_an_artifact_naming_neither_is_refused(self) -> None:
        with pytest.raises(SystemExit):
            core.subjects_of({"something": []})

    def test_every_registered_adapter_satisfies_the_protocol(self) -> None:
        for name in ECOSYSTEMS:
            adapter = core.load_adapter(name)
            assert name == adapter.ECOSYSTEM
            assert callable(adapter.discover)
            assert callable(adapter.classify)

    def test_an_unknown_ecosystem_is_refused(self) -> None:
        with pytest.raises(SystemExit):
            core.load_adapter("rego")

    def test_measure_reports_a_share_over_everything_and_over_what_it_judged(
        self, tmp_path: Path
    ) -> None:
        class Stub:
            ECOSYSTEM = "stub"

            def discover(self, root: Path) -> list[tuple[str, Path]]:
                return [("a", root / "a"), ("b", root / "b"), ("c", root / "c")]

            def classify(self, text: str) -> object:
                return {
                    "a": core.Verdict(core.INSIDE, "in"),
                    "b": core.Verdict(core.OUTSIDE, "out"),
                    "c": core.Verdict(core.UNDETERMINED, "unknown"),
                }[text.strip()]

        for name in ("a", "b", "c"):
            (tmp_path / name).write_text(name, encoding="utf-8")

        findings = core.measure(Stub(), tmp_path)

        assert findings["counts"] == {"inside": 1, "outside": 1, "undetermined": 1}
        assert findings["share_inside"] == pytest.approx(1 / 3, abs=1e-4)
        assert findings["share_inside_of_judged"] == pytest.approx(0.5, abs=1e-4)


class TestXacmlAdapter:
    NAMESPACE = 'xmlns:x="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"'

    def _policy(self, inner: str) -> str:
        return f'<?xml version="1.0"?><x:Policy {self.NAMESPACE} PolicyId="p">{inner}</x:Policy>'

    def _target(self, match_id: str) -> str:
        return (
            "<x:Target><x:AnyOf><x:AllOf>"
            f'<x:Match MatchId="urn:oasis:names:tc:xacml:1.0:function:{match_id}">'
            "<x:AttributeValue>medical-record</x:AttributeValue>"
            '<x:AttributeDesignator AttributeId="resource-type"/>'
            "</x:Match></x:AllOf></x:AnyOf></x:Target>"
        )

    def test_a_target_predicate_is_seen_even_though_it_is_named_matchid(self) -> None:
        """The first version scanned only FunctionId and saw no guard here at all."""

        outcome = xacml.classify(self._policy(self._target("string-equal")))

        assert outcome.verdict == core.INSIDE
        assert outcome.reason != "names no function at all"

    def test_selecting_over_request_content_is_outside(self) -> None:
        document = self._policy(self._target("string-equal") + '<x:AttributeSelector Path="//a"/>')

        outcome = xacml.classify(document)

        assert outcome.verdict == core.OUTSIDE
        assert "XPath" in outcome.reason

    def test_an_unrecognised_function_is_undetermined(self) -> None:
        outcome = xacml.classify(self._policy(self._target("xpath-node-count")))

        assert outcome.verdict == core.UNDETERMINED
        assert outcome.detail["unrecognised"] == ["xpath-node-count"]

    def test_malformed_xml_is_undetermined_rather_than_crashing(self) -> None:
        assert xacml.classify("<x:Policy><unclosed>").verdict == core.UNDETERMINED

    def test_a_regexp_match_is_admitted_because_the_pattern_is_regular(self) -> None:
        source = (SCRIPTS / "fragment_membership_xacml.py").read_text(encoding="utf-8")

        assert "string-regexp-match" in xacml.FINITELY_REFINING_FUNCTIONS
        assert "no backreferences" in source

    def test_the_subject_matches_the_suite_coverage_adapter(self, tmp_path: Path) -> None:
        policies = tmp_path / "basic" / "3" / "policies"
        policies.mkdir(parents=True)
        policy = policies / "TestPolicy_0007.xml"
        policy.write_text("<x/>", encoding="utf-8")

        assert xacml.subject_for(policy) == "basic/3/policy_0007"


class TestKyvernoAdapter:
    def test_a_context_entry_that_queries_the_cluster_is_outside(self) -> None:
        outcome = kyverno.classify("spec:\n  rules:\n  - context:\n    - apiCall: {}\n")

        assert outcome.verdict == core.OUTSIDE
        assert outcome.detail["external_context_sources"] == ["apiCall"]

    def test_a_registry_query_in_cel_is_outside(self) -> None:
        outcome = kyverno.classify("    expression: image.GetMetadata().config\n")

        assert outcome.verdict == core.OUTSIDE

    def test_reading_the_clock_is_outside(self) -> None:
        """now() makes the guard depend on when it ran, which is not part of the subject."""

        assert kyverno.classify("    expression: x.now()\n").verdict == core.OUTSIDE

    def test_the_built_in_images_variable_is_inside(self) -> None:
        """Kyverno parses it from the request; only imageRegistry queries a registry."""

        outcome = kyverno.classify('      - key: "{{ images.containers.*.registry }}"\n')

        assert outcome.verdict == core.INSIDE

    def test_a_request_variable_is_inside(self) -> None:
        assert kyverno.classify("{{ request.object.metadata.name }}").verdict == core.INSIDE

    def test_an_unrecognised_variable_is_undetermined(self) -> None:
        outcome = kyverno.classify("{{ somethingNobodyEnumerated.field }}")

        assert outcome.verdict == core.UNDETERMINED
        assert outcome.detail["unrecognised_variable_roots"] == ["somethingNobodyEnumerated"]

    def test_an_unrecognised_cel_call_is_undetermined(self) -> None:
        outcome = kyverno.classify("    expression: object.spec.mysteryCall()\n")

        assert outcome.verdict == core.UNDETERMINED

    def test_a_policy_is_resolved_through_its_test_manifest(self, tmp_path: Path) -> None:
        """38 of 49 scored policies exist at several paths, so the stem is not an identity."""

        for variant in ("other", "other-vpol"):
            directory = tmp_path / variant / "demo"
            (directory / ".kyverno-test").mkdir(parents=True)
            (directory / "demo.yaml").write_text(f"# {variant}\n", encoding="utf-8")
            (directory / ".kyverno-test" / "kyverno-test.yaml").write_text(
                "policies:\n- ../demo.yaml\n", encoding="utf-8"
            )

        found = kyverno.discover(tmp_path)

        assert [subject for subject, _ in found] == ["demo"]
        # The experiment keys by policy directory keeping the last in sorted order.
        assert found[0][1].parent.parent.name == "other-vpol"


class TestCedarAdapter:
    def test_a_scope_and_condition_policy_is_inside(self) -> None:
        outcome = cedar.classify(
            'permit (principal in Group::"admins", action, resource)\n'
            "when { resource has account && principal == resource.account.owner };\n"
        )

        assert outcome.verdict == core.INSIDE

    def test_extension_constructors_and_comparisons_are_inside(self) -> None:
        outcome = cedar.classify(
            "permit (principal, action, resource)\n"
            'when { context.amount.lessThanOrEqual(decimal("10.5")) };\n'
        )

        assert outcome.verdict == core.INSIDE
        assert "decimal" in outcome.detail["constructors"]

    def test_an_unrecognised_operator_is_undetermined(self) -> None:
        outcome = cedar.classify(
            "permit (principal, action, resource) when { resource.x.mysteryOp() };\n"
        )

        assert outcome.verdict == core.UNDETERMINED
        assert outcome.detail["unrecognised"] == ["mysteryOp"]

    def test_a_file_with_no_policy_statement_is_undetermined(self) -> None:
        assert cedar.classify("// only a comment\n").verdict == core.UNDETERMINED

    def test_comments_do_not_contribute_operators(self) -> None:
        outcome = cedar.classify(
            "// this mentions mysteryOp() in prose\npermit (principal, action, resource);\n"
        )

        assert outcome.verdict == core.INSIDE


@pytest.mark.parametrize("ecosystem", ECOSYSTEMS)
def test_the_committed_measurement_judges_every_policy(ecosystem: str) -> None:
    """A share computed over the policies an adapter understood would not be a measurement."""

    artifact = json.loads(
        (ROOT / "docs" / f"fragment-membership-{ecosystem}-v1.json").read_text(encoding="utf-8")
    )

    assert artifact["counts"]["undetermined"] == 0
    assert sum(artifact["counts"].values()) == artifact["policies_considered"]
    assert artifact["share_inside"] == artifact["share_inside_of_judged"]


def test_the_committed_measurements_hold_the_quoted_figures() -> None:
    figures = {"xacml": (21, 15, 6), "kyverno": (49, 41, 8), "cedar": (22, 22, 0)}
    for ecosystem, (total, inside, outside) in figures.items():
        artifact = json.loads(
            (ROOT / "docs" / f"fragment-membership-{ecosystem}-v1.json").read_text(encoding="utf-8")
        )
        assert artifact["policies_considered"] == total, ecosystem
        assert artifact["counts"]["inside"] == inside, ecosystem
        assert artifact["counts"]["outside"] == outside, ecosystem


def test_every_xacml_policy_outside_is_outside_for_the_same_reason() -> None:
    artifact = json.loads(
        (ROOT / "docs" / "fragment-membership-xacml-v1.json").read_text(encoding="utf-8")
    )
    reasons = {
        entry["reason"] for entry in artifact["policies"] if entry["verdict"] == core.OUTSIDE
    }

    assert reasons == {"selects over request content with XPath"}
