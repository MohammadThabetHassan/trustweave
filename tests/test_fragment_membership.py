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
import os
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
# The three ecosystems measured at both scopes. Rego is measured at whole-corpus scope
# only -- the suite study names its subjects by rule, not by module -- so the
# parametrised joined-scope cases below do not include it, and it has its own at the end.
ECOSYSTEMS = ("xacml", "kyverno", "cedar")
ALL_ECOSYSTEMS = ("xacml", "kyverno", "cedar", "rego", "iam")


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
        for name in ALL_ECOSYSTEMS:
            adapter = core.load_adapter(name)
            assert name == adapter.ECOSYSTEM
            assert callable(adapter.discover)
            assert callable(adapter.classify)

    def test_an_unknown_ecosystem_is_refused(self) -> None:
        # This case used to name "rego", which has since become a registered adapter.
        # A test whose fixture can be turned true by ordinary work is a test that stops
        # testing anything, so it now names a language nobody is going to add.
        with pytest.raises(SystemExit):
            core.load_adapter("not-a-policy-language")

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
        # `xpath-node-count` used to stand here, and it is now decided rather than
        # refused: it reads the request's Content, which places a policy outside. The
        # case this test exists for is a function from no known family at all, which is
        # still the one an adapter must refuse.
        outcome = xacml.classify(self._policy(self._target("invent-a-subject")))

        assert outcome.verdict == core.UNDETERMINED
        assert outcome.detail["unrecognised"] == ["invent-a-subject"]

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


# --- The wide corpus, and the two corrections that made it measurable -------------------
#
# Membership is decided from policy text, so restricting it to the policies a suite study
# could also score understates how much of an ecosystem the fragment covers. The wide
# measurement lifts that restriction. It required fixing the same mistake in two languages:
# an allowlist of function *names* where the criterion is about *kinds* of predicate.


WIDE_FIGURES = {"xacml": (548, 526, 22), "kyverno": (235, 205, 30), "cedar": (22, 22, 0)}


@pytest.mark.parametrize("ecosystem", ECOSYSTEMS)
def test_the_wide_measurement_judges_every_policy(ecosystem: str) -> None:
    artifact = json.loads(
        (ROOT / "docs" / f"fragment-membership-{ecosystem}-wide-v1.json").read_text("utf-8")
    )

    assert artifact["corpus_scope"] == "wide"
    assert artifact["counts"]["undetermined"] == 0
    assert sum(artifact["counts"].values()) == artifact["policies_considered"]


@pytest.mark.parametrize("ecosystem", ECOSYSTEMS)
def test_the_wide_measurement_holds_the_quoted_figures(ecosystem: str) -> None:
    total, inside, outside = WIDE_FIGURES[ecosystem]
    artifact = json.loads(
        (ROOT / "docs" / f"fragment-membership-{ecosystem}-wide-v1.json").read_text("utf-8")
    )

    assert artifact["policies_considered"] == total
    assert artifact["counts"]["inside"] == inside
    assert artifact["counts"]["outside"] == outside


@pytest.mark.parametrize("ecosystem", ECOSYSTEMS)
def test_every_measurement_pins_the_corpus_it_read(ecosystem: str) -> None:
    """A figure whose corpus is named only in prose cannot be reproduced from the artifact."""

    for scope in ("", "-wide"):
        artifact = json.loads(
            (ROOT / "docs" / f"fragment-membership-{ecosystem}{scope}-v1.json").read_text("utf-8")
        )
        corpus = artifact["corpus"]
        assert corpus, f"{ecosystem}{scope} names no corpus"
        for repository in corpus:
            assert repository["remote"].startswith("https://"), repository
            assert len(repository["commit"]) == 40, repository


@pytest.mark.parametrize("ecosystem", ECOSYSTEMS)
def test_widening_added_verdicts_and_moved_none(ecosystem: str) -> None:
    """The check that matters: the wide corpus contains the joined one, and agrees on it."""

    def verdicts(scope: str) -> dict[str, str]:
        artifact = json.loads(
            (ROOT / "docs" / f"fragment-membership-{ecosystem}{scope}-v1.json").read_text("utf-8")
        )
        return {entry["subject"]: entry["verdict"] for entry in artifact["policies"]}

    joined, wide = verdicts(""), verdicts("-wide")

    assert set(joined) <= set(wide), sorted(set(joined) - set(wide))
    moved = {name: (joined[name], wide[name]) for name in joined if joined[name] != wide[name]}
    assert moved == {}, moved


def test_xacml_membership_follows_the_family_not_the_datatype() -> None:
    """`integer-greater-than` and `time-greater-than` split the space the same way."""

    for datatype in ("integer", "double", "time", "date", "dateTime", "string"):
        assert xacml.is_finitely_refining(f"{datatype}-greater-than"), datatype
        assert xacml.is_finitely_refining(f"{datatype}-one-and-only"), datatype
        assert xacml.is_finitely_refining(f"{datatype}-bag"), datatype
        assert xacml.is_finitely_refining(f"{datatype}-is-in"), datatype


def test_xacml_still_refuses_a_function_from_no_known_family() -> None:
    assert not xacml.is_finitely_refining("string-invent-a-subject")
    assert not xacml.is_finitely_refining("policy-defined-extension")


def test_xacml_xpath_functions_are_outside_not_merely_unjudged() -> None:
    """They read the request's Content, which the policy does not contain."""

    policy = """<?xml version="1.0"?>
    <Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="p">
      <Target/>
      <Rule Effect="Permit" RuleId="r">
        <Condition>
          <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:integer-equal">
            <Apply FunctionId="urn:oasis:names:tc:xacml:3.0:function:xpath-node-count"/>
          </Apply>
        </Condition>
      </Rule>
    </Policy>"""

    outcome = xacml.classify(policy)

    assert outcome.verdict == core.OUTSIDE
    assert "xpath-node-count" in outcome.detail["external_functions"]


def test_a_policy_stating_no_predicate_is_inside_with_one_class() -> None:
    """XACML's IIB001: an empty Target and an unguarded rule. Always Permit."""

    policy = """<?xml version="1.0"?>
    <Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="p">
      <Target/>
      <Rule Effect="Permit" RuleId="r"/>
    </Policy>"""

    outcome = xacml.classify(policy)

    assert outcome.verdict == core.INSIDE
    assert "one decision class" in outcome.reason


def test_a_guard_whose_function_cannot_be_read_is_not_called_predicate_free() -> None:
    """The dangerous conflation: an empty function scan has two very different causes."""

    policy = """<?xml version="1.0"?>
    <Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="p">
      <Target>
        <AnyOf><AllOf><Match><AttributeValue>x</AttributeValue></Match></AllOf></AnyOf>
      </Target>
      <Rule Effect="Permit" RuleId="r"/>
    </Policy>"""

    outcome = xacml.classify(policy)

    assert outcome.verdict == core.UNDETERMINED
    assert outcome.detail["guard_elements"] == ["Match"]


def test_kyverno_resource_list_and_post_reach_the_api_server() -> None:
    for call in ("List", "Post", "Get"):
        outcome = kyverno.classify(
            "spec:\n  rules:\n  - name: r\n    validate:\n      cel:\n"
            "        expressions:\n"
            f"        - expression: resource.{call}('v1','pods')\n"
        )
        assert outcome.verdict == core.OUTSIDE, call


def test_kyverno_reads_an_image_reference_without_querying_a_registry() -> None:
    """`image(x).registry()` parses a string already in the admission request."""

    outcome = kyverno.classify(
        "spec:\n  rules:\n  - name: r\n    validate:\n      cel:\n"
        "        expressions:\n"
        '        - expression: image(object.spec.containers[0].image).registry() == "r.io"\n'
    )

    assert outcome.verdict == core.INSIDE


def test_kyverno_treats_generation_as_an_effect_not_a_guard() -> None:
    outcome = kyverno.classify(
        "spec:\n  rules:\n  - name: r\n    generate:\n"
        "    - expression: generator.Apply(variables.targetNs, variables.downstream)\n"
    )

    assert outcome.verdict == core.INSIDE


def test_kyverno_resolves_a_context_variable_the_policy_binds_itself() -> None:
    """Sound only because an external context source returns outside before this point."""

    outcome = kyverno.classify(
        "spec:\n  rules:\n  - name: r\n    context:\n"
        "    - name: tokenvolname\n      variable:\n"
        "        jmesPath: request.object.spec.volumes[0].name\n"
        "    preconditions:\n      all:\n"
        '      - key: "{{ tokenvolname }}"\n        operator: Equals\n        value: "?*"\n'
    )

    assert outcome.verdict == core.INSIDE
    assert outcome.detail["context_bound_names"] == ["tokenvolname"]


def test_kyverno_refuses_a_context_binding_that_reads_past_the_request() -> None:
    outcome = kyverno.classify(
        "spec:\n  rules:\n  - name: r\n    context:\n"
        "    - name: whatever\n      variable:\n"
        "        jmesPath: someUnknownRoot.field\n"
        '    preconditions:\n      all:\n      - key: "{{ whatever }}"\n'
        '        operator: Equals\n        value: "x"\n'
    )

    assert outcome.verdict == core.UNDETERMINED
    assert outcome.detail["unresolved_context_bindings"] == ["someUnknownRoot"]


def test_kyverno_accepts_a_nested_foreach_cursor() -> None:
    outcome = kyverno.classify(
        "spec:\n  rules:\n  - name: r\n    mutate:\n      foreach:\n"
        "      - list: request.object.spec.containers\n"
        "        patchesJson6902: |-\n"
        "          - path: /spec/containers/{{elementIndex0}}/volumeMounts/{{elementIndex1}}\n"
        "            op: remove\n"
    )

    assert outcome.verdict == core.INSIDE


def test_the_wide_discovery_falls_back_for_an_adapter_without_one() -> None:
    """`discover_wide` is optional, so the core must not require it."""

    class Narrow:
        ECOSYSTEM = "narrow"

        @staticmethod
        def discover(root: Path) -> list[tuple[str, Path]]:
            return []

        @staticmethod
        def classify(text: str) -> object:
            raise AssertionError("not reached")

    assert core.discovery_for(Narrow, wide=True) is Narrow.discover
    assert core.discovery_for(Narrow, wide=False) is Narrow.discover
    assert core.discovery_for(xacml, wide=True) is xacml.discover_wide
    assert core.discovery_for(xacml, wide=False) is xacml.discover


# --- Rego, the fourth ecosystem ---------------------------------------------------------
#
# Rego was asserted to fall outside the fragment rather than measured, and the assertion
# was wrong: 116 of 186 published policies are inside. The adapter needs `opa` to parse,
# so the cases that need a parser skip without it, while the committed artifact is checked
# either way -- a figure in a document must not depend on a binary being installed.

rego = _load("fragment_membership_rego")

opa_required = pytest.mark.skipif(
    shutil.which("opa") is None, reason="opa is not installed; the rego adapter needs it"
)


def test_the_rego_measurement_judges_every_policy() -> None:
    artifact = json.loads(
        (ROOT / "docs" / "fragment-membership-rego-wide-v1.json").read_text("utf-8")
    )

    assert artifact["corpus_scope"] == "wide"
    assert artifact["counts"] == {"inside": 116, "outside": 70, "undetermined": 0}
    assert artifact["policies_considered"] == 186


def test_the_rego_measurement_counts_no_test_module_as_a_policy() -> None:
    """`opa test` cases are not policies, and both naming conventions appear upstream."""

    artifact = json.loads(
        (ROOT / "docs" / "fragment-membership-rego-wide-v1.json").read_text("utf-8")
    )
    named_like_a_test = [
        entry["subject"]
        for entry in artifact["policies"]
        if entry["subject"].endswith("_test.rego") or "/test_" in entry["subject"]
    ]

    assert named_like_a_test == []


def test_the_rego_exclusions_are_the_kinds_the_document_names() -> None:
    """28 policy schemas, 34 reaching the injected inventory, 8 other data documents."""

    artifact = json.loads(
        (ROOT / "docs" / "fragment-membership-rego-wide-v1.json").read_text("utf-8")
    )
    reasons = [entry["reason"] for entry in artifact["policies"] if entry["verdict"] == "outside"]

    parameters = sum(1 for reason in reasons if "policy schema" in reason)
    injected = sum(1 for reason in reasons if "the host injects" in reason)
    via_library = sum(1 for reason in reasons if "reaches outside" in reason)

    assert parameters == 28
    assert injected + via_library == 34
    assert via_library == 25, "the import graph is what makes these 25 outside"
    assert len(reasons) - parameters - injected - via_library == 8


@opa_required
def test_rego_reads_the_request_and_literals_and_is_inside() -> None:
    outcome = rego.classify(
        "package p\n\n"
        "violation[{'msg': msg}] {\n"
        '  input.review.kind.kind == "Service"\n'
        '  input.review.object.spec.type == "NodePort"\n'
        '  msg := "not allowed"\n'
        "}\n".replace("'", '"')
    )

    assert outcome.verdict == core.INSIDE


@opa_required
def test_rego_parameterised_by_a_constraint_is_a_schema_not_a_policy() -> None:
    """Not because a guard reads something it should not -- finite refinement holds here.

    The template determines no decision function until a Constraint is applied, and
    membership is a property of a policy. Calling it "a pattern taken from the input" was
    the first explanation and it does not survive the definition.
    """

    outcome = rego.classify(
        "package p\n\n"
        'violation[{"msg": msg}] {\n'
        "  repo := input.parameters.repos[_]\n"
        "  not startswith(input.review.object.spec.containers[0].image, repo)\n"
        '  msg := "bad repo"\n'
        "}\n"
    )

    assert outcome.verdict == core.OUTSIDE
    assert "policy schema" in outcome.reason


@opa_required
def test_rego_reading_the_injected_inventory_is_outside() -> None:
    outcome = rego.classify(
        "package p\n\n"
        'violation[{"msg": msg}] {\n'
        '  ns := data.inventory.cluster["v1"].Namespace["prod"]\n'
        '  msg := sprintf("%v", [ns])\n'
        "}\n"
    )

    assert outcome.verdict == core.OUTSIDE
    assert "injects" in outcome.reason


@opa_required
def test_rego_calling_a_nondeterministic_builtin_is_outside() -> None:
    for call in ("http.send({})", "time.now_ns()", 'rand.intn("s", 10)', "opa.runtime()"):
        outcome = rego.classify(
            'package p\n\nviolation[{"msg": msg}] {\n'
            f"  x := {call}\n"
            '  msg := sprintf("%v", [x])\n'
            "}\n"
        )
        assert outcome.verdict == core.OUTSIDE, call


@opa_required
def test_rego_pure_time_and_net_builtins_stay_inside() -> None:
    """Only a handful of `time.*` and `net.*` reach past their arguments."""

    outcome = rego.classify(
        "package p\n\n"
        'violation[{"msg": msg}] {\n'
        '  net.cidr_contains("10.0.0.0/8", input.review.object.spec.clusterIP)\n'
        '  msg := "in range"\n'
        "}\n"
    )

    assert outcome.verdict == core.INSIDE


@opa_required
def test_rego_identifies_a_test_module_by_its_rules() -> None:
    fixture = 'package p\n\ntest_something {\n  true\n}\n\ninput_review := {"kind": "Pod"}\n'
    ast = rego.parse(fixture)

    assert ast is not None
    assert rego.is_test_module(ast)
    assert not rego.is_test_module(rego.parse("package p\n\nallow {\n  input.x == 1\n}\n"))


@opa_required
def test_rego_normalises_package_and_import_paths_the_same_way() -> None:
    """Comparing a `data.` reference against a package means dropping `data.` from both."""

    ast = rego.parse("package lib.helpers\n\nimport data.lib.other\n\nx := 1\n")

    assert ast is not None
    assert rego.package_of(ast) == "lib.helpers"
    assert rego.imports_of(ast) == ["lib.other"]


@opa_required
def test_every_excluded_policy_schema_has_an_instantiation_in_the_corpus() -> None:
    """The claim that makes the schema exclusion honest, checked rather than asserted.

    A constraint template is excluded because it is a policy schema, not because a guard
    reads something it should not -- the guard's outcome map over the input document has
    finite image with constructible witnesses, so finite refinement holds. What fails is
    that the artifact determines no decision function until a Constraint is applied. That
    claim is only worth making if the instantiation exists, so this checks that it does:
    the corpus ships a Constraint supplying parameters for every one of them.
    """
    import fragment_membership as core_module

    root = Path(os.environ.get("TRUSTWEAVE_REGO_CORPUS", ""))
    if not root.is_dir():
        pytest.skip("set TRUSTWEAVE_REGO_CORPUS to the pinned Rego corpus to check this")

    discovered = rego.discover(root)
    assert discovered, "the corpus root holds no Rego policies"

    schemas = []
    for subject, path in discovered:
        outcome = rego.classify(path.read_text(encoding="utf-8", errors="ignore"))
        if outcome.verdict == core_module.OUTSIDE and "policy schema" in outcome.reason:
            schemas.append(subject)

    assert schemas, "the corpus is expected to contain parameterised templates"
    without = [s for s in schemas if not rego.constraints_for(s)]
    assert without == [], f"{len(without)} schemas have no instantiating Constraint: {without[:3]}"


def test_the_artifact_records_the_schemas_separately_from_the_other_exclusions() -> None:
    """Two kinds of exclusion, and pooling them without saying so would mislead."""

    artifact = json.loads(
        (ROOT / "docs" / "fragment-membership-rego-wide-v1.json").read_text("utf-8")
    )
    outside = [p for p in artifact["policies"] if p["verdict"] == "outside"]
    schemas = [p for p in outside if "policy schema" in p["reason"]]
    reads_outside = [p for p in outside if "policy schema" not in p["reason"]]

    assert len(schemas) == 28
    assert len(reads_outside) == 42
    assert len(schemas) + len(reads_outside) == artifact["counts"]["outside"] == 70
    # And the share over artifacts that are actually policies.
    policies = artifact["policies_considered"] - len(schemas)
    assert policies == 158
    assert round(100 * artifact["counts"]["inside"] / policies, 1) == 73.4


# --- AWS IAM: the deployed-policy corpus -----------------------------------------------
#
# The other four corpora are vendor test and conformance directories. AWS managed policies
# are published by AWS and attached in accounts worldwide, which is why they were added:
# they answer the external-validity objection the other four cannot.

iam = _load("fragment_membership_iam")


def test_the_iam_measurement_judges_every_policy() -> None:
    artifact = json.loads(
        (ROOT / "docs" / "fragment-membership-iam-wide-v1.json").read_text("utf-8")
    )

    assert artifact["corpus_scope"] == "wide"
    assert artifact["policies_considered"] == 1651
    assert artifact["counts"] == {"inside": 1651, "outside": 0, "undetermined": 0}


def test_the_iam_adapter_has_no_path_to_outside_and_the_paper_says_so() -> None:
    """The caveat that keeps the 100% honest, asserted where it cannot be forgotten.

    IAM offers no construct by which a policy reads state the evaluator was not handed --
    no lookup, no clock call, no external fetch, and every condition key travels with the
    request -- so the adapter has no `outside` branch. That makes the figure weaker
    evidence than Kyverno's 87.2%, where the instrument had one and used it 30 times. If
    someone later adds an `outside` branch, this test should fail and the paper's caveat
    should be revisited.
    """
    source = (ROOT / "scripts" / "fragment_membership_iam.py").read_text("utf-8")
    body = source.split('"""', 2)[-1]

    assert "OUTSIDE" not in body.replace(
        "from fragment_membership import INSIDE, OUTSIDE, UNDETERMINED, Verdict", ""
    ), "the adapter gained an outside branch; the paper's caveat needs updating"


def test_iam_membership_follows_the_operator_family_not_the_datatype() -> None:
    for family in ("StringEquals", "ArnLike", "NumericLessThan", "DateGreaterThan", "Null"):
        assert iam.is_finitely_refining(family), family
        assert iam.is_finitely_refining(f"ForAllValues:{family}"), family
        assert iam.is_finitely_refining(f"{family}IfExists"), family
        assert iam.is_finitely_refining(f"ForAnyValue:{family}IfExists"), family


def test_iam_refuses_an_operator_from_no_known_family() -> None:
    outcome = iam.classify(
        json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:*",
                        "Resource": "*",
                        "Condition": {"InventALookup": {"aws:Thing": "x"}},
                    }
                ]
            }
        )
    )

    assert outcome.verdict == core.UNDETERMINED
    assert outcome.detail["unjudged_operators"] == ["InventALookup"]


def test_iam_refuses_a_condition_it_cannot_read() -> None:
    for condition in ("nonsense", {"StringEquals": "nonsense"}):
        outcome = iam.classify(
            json.dumps(
                {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Condition": condition}]}
            )
        )
        assert outcome.verdict == core.UNDETERMINED, condition


def test_an_interpolated_policy_variable_stays_inside() -> None:
    """It relates two components of the same request, so a witness is constructible.

    This is the case the project got wrong once already, for Gatekeeper's parameters. The
    substituted value here is an attribute of the request being authorized, not a separate
    document supplied at bind time.
    """
    outcome = iam.classify(
        json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::bucket/${aws:username}/*",
                    }
                ]
            }
        )
    )

    assert outcome.verdict == core.INSIDE


def test_iam_reads_a_document_whether_or_not_it_is_wrapped_in_metadata() -> None:
    bare = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}

    assert iam.document_of(json.dumps(bare)) == bare
    assert iam.document_of(json.dumps({"name": "p", "document": bare})) == bare
    assert iam.document_of(json.dumps({"policies": []})) is None
    assert iam.document_of("not json") is None


def test_every_operator_the_corpus_uses_is_judged_by_a_family() -> None:
    """No operator slipped through as unrecognised, and none was accepted by accident."""

    artifact = json.loads(
        (ROOT / "docs" / "fragment-membership-iam-wide-v1.json").read_text("utf-8")
    )
    operators = {
        operator
        for entry in artifact["policies"]
        for operator in entry.get("condition_operators", [])
    }

    assert len(operators) == 27, sorted(operators)
    assert all(iam.is_finitely_refining(operator) for operator in operators)
    assert {iam.base_operator(o) for o in operators} <= iam.FINITELY_REFINING_FAMILIES


# --- Policy written by people who do not ship the engine --------------------------------
#
# Every other corpus here is published by the vendor whose engine reads it, IAM included.
# This one is Kyverno policy from unaffiliated organisations, and it exists to answer one
# question: does the fragment cover only what vendors write? It is a convenience sample
# from code search and the artifact says so.


def test_the_third_party_corpus_is_pinned_file_by_file() -> None:
    """Code search results are not stable, so reproducibility cannot rest on them."""

    corpus = json.loads((ROOT / "docs" / "third-party-kyverno-corpus-v1.json").read_text("utf-8"))

    assert corpus["provenance"] == "third-party"
    assert corpus["excluded_owners"] == ["kyverno", "nirmata"]
    assert corpus["policies"] == len(corpus["files"]) == 49
    for entry in corpus["files"]:
        assert len(entry["commit"]) == 40, entry
        assert len(entry["sha256"]) == 64, entry
        assert entry["repo"].count("/") == 1, entry
        assert entry["repo"].split("/")[0].lower() not in {"kyverno", "nirmata"}, entry


def test_the_third_party_measurement_judges_every_policy() -> None:
    artifact = json.loads(
        (ROOT / "docs" / "fragment-membership-kyverno-thirdparty-v1.json").read_text("utf-8")
    )

    assert artifact["policies_considered"] == 49
    assert artifact["counts"] == {"inside": 37, "outside": 12, "undetermined": 0}
    assert artifact["owners"] == 28
    assert artifact["repositories"] == 31
    assert artifact["policies_unavailable"] == []


def test_every_third_party_exclusion_is_image_verification() -> None:
    """The construct that required somebody else's policy to find.

    `verifyImages` checks a signature or attestation against a registry and a transparency
    log, and the fetched attestation is not in the admission request. It barely appears in
    the vendor's tested subset, so the gap only showed on a corpus the vendor did not write.
    """
    artifact = json.loads(
        (ROOT / "docs" / "fragment-membership-kyverno-thirdparty-v1.json").read_text("utf-8")
    )
    outside = [entry for entry in artifact["policies"] if entry["verdict"] == "outside"]

    assert len(outside) == 12
    assert all("verifies an image" in entry["reason"] for entry in outside)
    assert all(entry.get("image_verification") is True for entry in outside)


def test_the_third_party_share_is_lower_than_the_vendor_share() -> None:
    """The direction that makes the comparison worth having rather than reassuring."""

    third_party = json.loads(
        (ROOT / "docs" / "fragment-membership-kyverno-thirdparty-v1.json").read_text("utf-8")
    )
    vendor = json.loads(
        (ROOT / "docs" / "fragment-membership-kyverno-wide-v1.json").read_text("utf-8")
    )

    assert third_party["share_inside"] < vendor["share_inside"]


def test_kyverno_verifying_an_image_reads_past_the_request() -> None:
    outcome = kyverno.classify(
        "spec:\n  rules:\n  - name: r\n    verifyImages:\n"
        "    - imageReferences:\n      - '*'\n"
        "      attestations:\n      - predicateType: https://example.com/p\n"
        "        conditions:\n        - all:\n"
        '          - key: "{{ Data.sbom }}"\n            operator: Equals\n'
        '            value: "x"\n'
    )

    assert outcome.verdict == core.OUTSIDE
    assert "registry" in outcome.reason


def test_kyverno_reading_the_clock_is_outside() -> None:
    for function in ("time_now", "time_now_utc", "time_since"):
        outcome = kyverno.classify(
            "spec:\n  rules:\n  - name: r\n    preconditions:\n      all:\n"
            f"      - key: \"{{{{ {function}('', '', '') }}}}\"\n"
            '        operator: GreaterThan\n        value: "1h"\n'
        )
        assert outcome.verdict == core.OUTSIDE, function
        assert function in outcome.detail["clock_functions"]


def test_pure_kyverno_time_functions_stay_inside() -> None:
    """Only the ones that consult "now" reach past their arguments."""

    outcome = kyverno.classify(
        "spec:\n  rules:\n  - name: r\n    preconditions:\n      all:\n"
        "      - key: \"{{ time_parse('2006-01-02', request.object.metadata.x) }}\"\n"
        '        operator: Equals\n        value: "y"\n'
    )

    assert outcome.verdict == core.INSIDE
