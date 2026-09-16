"""Tests for the cross-ecosystem fragment-membership instrument.

These measurements are the only evidence behind section 4b of
the decision-class coverage write-up, and behind the stratified reading of the Kyverno
association in the suite-coverage study. The corpora are not in the repository -- they
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


def _pinned_corpus(variable: str) -> Path:
    """A corpus root from the environment, or skip.

    `Path("")` is `.`, not a missing path, so testing the result of `os.environ.get` with a
    default of `""` for `is_dir()` silently runs against the working directory instead of
    skipping. That is how the vendor-corpus case below failed in a checkout with no corpus.
    """

    value = os.environ.get(variable, "").strip()
    if not value:
        pytest.skip(f"set {variable} to the pinned corpus to run this")
    root = Path(value)
    if not root.is_dir():
        pytest.skip(f"{variable} does not name a directory")
    return root


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

    def test_a_parenthesised_expression_over_the_request_is_inside(self) -> None:
        """`( ... ) | sort(@)` opens with a bracket, and the root is what follows it."""

        outcome = kyverno.classify(
            "spec:\n  rules:\n  - name: r\n    preconditions:\n      all:\n"
            '      - key: "{{ (request.object.spec.rules[].host || `[]`) | sort(@) }}"\n'
            '        operator: Equals\n        value: "{{ request.object.spec.tls }}"\n'
        )

        assert outcome.verdict == core.INSIDE, outcome.detail

    def test_a_pure_string_filter_over_the_request_is_inside(self) -> None:
        """`regex_replace_all` rewrites the string it is handed and reads nothing else."""

        outcome = kyverno.classify(
            "spec:\n  rules:\n  - name: r\n    mutate:\n      foreach:\n"
            "      - list: request.object.spec.containers\n        patchStrategicMerge:\n"
            "          spec:\n            containers:\n"
            '            - name: "{{ element.name }}"\n'
            "              image: \"{{ regex_replace_all('^x/(.*)$', "
            "'{{element.image}}', 'y/$1') }}\"\n"
        )

        assert outcome.verdict == core.INSIDE, outcome.detail

    def test_a_policy_is_resolved_through_its_test_manifest(self, tmp_path: Path) -> None:
        """Most scored policies exist at several paths, so no stem or directory is an identity."""

        for variant in ("other", "other-vpol"):
            directory = tmp_path / variant / "demo"
            (directory / ".kyverno-test").mkdir(parents=True)
            (directory / "demo.yaml").write_text(f"# {variant}\n", encoding="utf-8")
            (directory / ".kyverno-test" / "kyverno-test.yaml").write_text(
                "kind: Test\npolicies:\n- ../demo.yaml\nresults:\n- policy: demo\n  result: pass\n",
                encoding="utf-8",
            )

        found = kyverno.discover(tmp_path)

        assert [subject for subject, _ in found] == ["demo"]
        # The experiment keys by the name the manifest states and measures the first manifest
        # in path order, which is the base directory; the verdict must describe that file.
        assert found[0][1].parent.parent.name == "other"

    def test_discovery_keys_exactly_as_the_mutation_experiment_does(self, tmp_path: Path) -> None:
        """One function decides which file a name means, or the stratified join is unsound."""

        for variant, stated in (("other", "alpha"), ("other-cel", "alpha"), ("other", "beta")):
            directory = tmp_path / variant / stated
            (directory / ".kyverno-test").mkdir(parents=True, exist_ok=True)
            (directory / f"{stated}.yaml").write_text(f"# {variant}/{stated}\n", encoding="utf-8")
            (directory / ".kyverno-test" / "kyverno-test.yaml").write_text(
                f"kind: Test\npolicies:\n- ../{stated}.yaml\nresults:\n- policy: {stated}\n"
                "  result: pass\n",
                encoding="utf-8",
            )
        mutation = _load("kyverno_mutation")

        discovered = {subject: path for subject, path in kyverno.discover(tmp_path)}
        measured = {name: paths[0] for name, paths in mutation.policy_manifests(tmp_path).items()}

        assert set(discovered) == set(measured) == {"alpha", "beta"}
        for name, path in discovered.items():
            assert path.parent == measured[name].parent


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

    def test_a_url_inside_a_string_does_not_start_a_comment(self) -> None:
        """`COMMENT = re.compile(r"//.*")` had no string state, and failed unsafely.

        A `//` inside a string literal deleted the rest of the physical line before any
        operator scan ran, so a policy that should be refused came back `inside` -- a
        confident wrong verdict rather than an abstention, because truncation is line-local.
        """

        refused = cedar.classify(
            "permit(principal, action, resource) when { resource.tags.someUnknownExtension(1) };\n"
        )
        assert refused.verdict == core.UNDETERMINED
        assert refused.detail["unrecognised"] == ["someUnknownExtension"]

        with_url = cedar.classify(
            "permit(principal, action, resource) when "
            '{ resource.url like "https://x/*" && resource.tags.someUnknownExtension(1) };\n'
        )
        assert with_url.verdict == core.UNDETERMINED, "a URL must not swallow the guard"
        assert with_url.detail["unrecognised"] == ["someUnknownExtension"]

        # An entity UID holding a URL is the same shape, and a later statement on one line
        # must survive the earlier one's string.
        uid = cedar.classify(
            'permit(principal, action, resource == Doc::"https://ex.com/a") '
            "when { resource.t.weirdCall(1) };\n"
        )
        assert uid.verdict == core.UNDETERMINED

    def test_a_real_comment_after_a_string_is_still_a_comment(self) -> None:
        """The other direction: string awareness must not stop comments being stripped."""

        outcome = cedar.classify(
            'permit(principal, action, resource) when { resource.url == "https://x/y" }; '
            "// mentions mysteryOp() in prose\n"
        )

        assert outcome.verdict == core.INSIDE
        assert outcome.detail["constructors"] == []


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
    figures = {"xacml": (21, 15, 6), "kyverno": (52, 39, 13), "cedar": (22, 22, 0)}
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


WIDE_FIGURES = {"xacml": (1007, 953, 54), "kyverno": (237, 206, 31), "cedar": (22, 22, 0)}


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


def test_the_clock_is_one_obstruction_in_every_language_including_xacml() -> None:
    """The claim the paper makes, checked in the language that was the exception.

    Azure's `utcNow()`, Rego's `time.now_ns` and Kyverno's `now()` were all reported as
    reading evaluation-time state. XACML's clock arrives through an attribute designator
    rather than a function, so a scan over function identifiers could not see it, and 15
    conformance policies that read it were reported inside.
    """

    policy = (
        '<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="p" '
        'RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:'
        'deny-overrides"><Target/><Rule RuleId="r" Effect="Permit"><Condition>'
        '<Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:time-greater-than">'
        "<AttributeDesignator "
        'AttributeId="urn:oasis:names:tc:xacml:1.0:environment:current-time" '
        'Category="urn:oasis:names:tc:xacml:3.0:attribute-category:environment" '
        'DataType="http://www.w3.org/2001/XMLSchema#time" MustBePresent="false"/>'
        "</Apply></Condition></Rule></Policy>"
    )

    outcome = xacml.classify(policy)

    assert outcome.verdict == "outside"
    assert "reads the clock" in outcome.reason
    assert outcome.detail["clock_designators"] == [
        "urn:oasis:names:tc:xacml:1.0:environment:current-time"
    ]
    assert taxonomy.classify(outcome.reason) == "reads evaluation-time state"

    artifact = json.loads(
        (ROOT / "docs" / "fragment-membership-xacml-wide-v1.json").read_text("utf-8")
    )
    clock = [entry for entry in artifact["policies"] if "reads the clock" in entry["reason"]]
    assert len(clock) == 15
    assert all(entry["verdict"] == "outside" for entry in clock)


def test_a_xacml_policy_is_selected_by_what_it_is_not_what_it_is_called() -> None:
    """Selection by filename decided the corpus, and decided out every clock reader.

    The wide corpus took `TestPolicy_*.xml` under a `policies/` directory and files named
    `Policy.xml`, which is how the two projects happen to name most conformance cases. 459
    policies were left out by that, among them all 15 that read the clock, so the row
    reported no clock reader because none had been selected.
    """

    artifact = json.loads(
        (ROOT / "docs" / "fragment-membership-xacml-wide-v1.json").read_text("utf-8")
    )

    assert artifact["policies_considered"] == 1007
    names = [entry["subject"].rsplit("/", 1)[-1] for entry in artifact["policies"]]
    assert any(not name.startswith(("TestPolicy_", "Policy.xml")) for name in names)
    # And the joined corpus is still contained in it, under the names the study gave it.
    joined = json.loads((ROOT / "docs" / "fragment-membership-xacml-v1.json").read_text("utf-8"))
    wide = {entry["subject"] for entry in artifact["policies"]}
    assert {entry["subject"] for entry in joined["policies"]} <= wide


def test_kyverno_reads_context_from_the_parse_and_not_from_the_prose() -> None:
    """A description sentence is not a data fetch, and neither is a mutation payload.

    The external-context test asked whether the string `configMap` occurred anywhere in the
    file. It occurs in a policy's own description, in a CEL expression reading
    `object.spec.volumes.configMap`, and in a payload injecting `configMapRef` into a pod --
    none of which fetches anything. Three of the corpus's exclusions were that mistake.
    """

    prose = (
        "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: p\n"
        "  annotations:\n    policies.kyverno.io/description: >-\n"
        "      Stored in a ConfigMap so that you can automount them.\n"
        "spec:\n  rules:\n  - name: r\n    match:\n      any:\n"
        "      - resources:\n          kinds:\n          - Pod\n"
        "    validate:\n      pattern:\n        spec:\n          containers:\n"
        "          - name: '*'\n"
    )
    fetches = (
        "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: q\n"
        "spec:\n  rules:\n  - name: r\n    match:\n      any:\n"
        "      - resources:\n          kinds:\n          - Pod\n"
        "    context:\n    - name: cm\n      configMap:\n        name: settings\n"
        "        namespace: default\n"
        "    validate:\n      pattern:\n        spec:\n          containers:\n"
        "          - name: '*'\n"
    )

    assert kyverno.classify(prose).verdict == "inside"
    fetched = kyverno.classify(fetches)
    assert fetched.verdict == "outside"
    assert "context entry fetches" in fetched.reason

    nested = fetches.replace(
        "    context:\n    - name: cm\n      configMap:",
        "    mutate:\n      foreach:\n      - list: request.object.spec.containers\n"
        "        context:\n        - name: cm\n          configMap:",
    )
    assert kyverno.classify(nested).verdict == "outside", "context inside a foreach still counts"


def test_kyverno_selecting_on_namespace_labels_is_outside() -> None:
    """The AdmissionReview carries the namespace's name, not the namespace object."""

    policy = (
        "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: p\n"
        "spec:\n  rules:\n  - name: r\n    match:\n      any:\n"
        "      - resources:\n          kinds:\n          - Pod\n"
        "          namespaceSelector:\n            matchLabels:\n              tier: prod\n"
        "    validate:\n      pattern:\n        spec:\n          containers:\n"
        "          - name: '*'\n"
    )

    outcome = kyverno.classify(policy)

    assert outcome.verdict == "outside"
    assert "Namespace labels" in outcome.reason
    assert taxonomy.classify(outcome.reason) == "the subject does not determine the guard"


def test_kyverno_selecting_on_the_requesters_cluster_roles_is_outside() -> None:
    """Kyverno fetches these; the AdmissionReview does not carry them.

    The adapter had a branch for `namespaceSelector` and none for `roles`/`clusterRoles`,
    which fail the identical test: `pkg/webhooks/handlers/enrich.go` fills `request.Roles`
    and `request.ClusterRoles` from `userinfo.GetRoleRef()`, which lists RoleBindings and
    ClusterRoleBindings out of the cluster. Three vendor policies gate on cluster RBAC --
    `block-updates-deletes`, `deny-privileged-profile`, `disallow-default-tlsoptions`, each
    `background: false` -- and all three shipped `inside` with the affirmative reason that
    every guard reads the admission request and literals in the policy.
    """

    policy = (
        "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: p\n"
        "spec:\n  background: false\n  rules:\n  - name: r\n    match:\n      any:\n"
        "      - resources:\n          kinds:\n          - Pod\n"
        "    exclude:\n      any:\n      - clusterRoles:\n        - cluster-admin\n"
        "    validate:\n      pattern:\n        spec:\n          containers:\n"
        "          - name: '*'\n"
    )

    outcome = kyverno.classify(policy)

    assert outcome.verdict == "outside"
    assert "role bindings" in outcome.reason
    assert outcome.detail["rbac_selectors"] == ["exclude.clusterRoles"]
    assert taxonomy.classify(outcome.reason) == "the subject does not determine the guard"


def test_kyverno_selecting_on_the_requesters_own_identity_stays_inside() -> None:
    """The refusal direction. `subjects` is matched against the request's own userInfo."""

    policy = (
        "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: p\n"
        "spec:\n  rules:\n  - name: r\n    match:\n      any:\n"
        "      - resources:\n          kinds:\n          - Pod\n"
        "        subjects:\n        - kind: User\n          name: alice\n"
        "    validate:\n      pattern:\n        spec:\n          containers:\n"
        "          - name: '*'\n"
    )

    assert kyverno.classify(policy).verdict == core.INSIDE
    # And a resource *kind* called Role is a value, not a selector key.
    kinds_only = (
        "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: p\n"
        "spec:\n  rules:\n  - name: r\n    match:\n      any:\n"
        "      - resources:\n          kinds:\n          - Role\n          - ClusterRole\n"
        "    validate:\n      pattern:\n        rules:\n        - verbs:\n          - get\n"
    )
    assert kyverno.classify(kinds_only).verdict == core.INSIDE


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
    assert artifact["counts"] == {"inside": 115, "outside": 71, "undetermined": 0}
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
    """26 schemas, 35 reaching the inventory, 9 other data documents, one network call.

    Of the 35, 11 read `data.inventory` in their own body and 24 through one library rule;
    the count was 25 while propagation followed imports rather than the rules a policy
    evaluates, and the engine's dependency analysis disagreed on the twenty-fifth. Of the 9
    other documents, 8 are read directly and one through a rule in a sibling package. The
    network call is `http.send` as a top-level statement, which the first walker did not see.
    """

    artifact = json.loads(
        (ROOT / "docs" / "fragment-membership-rego-wide-v1.json").read_text("utf-8")
    )
    reasons = [entry["reason"] for entry in artifact["policies"] if entry["verdict"] == "outside"]

    parameters = sum(1 for reason in reasons if "policy schema" in reason)
    injected_directly = sum(
        1 for reason in reasons if reason.startswith("reads a document the host injects")
    )
    via_rule = [reason for reason in reasons if reason.startswith("reaches outside through")]
    via_rule_injected = sum(1 for reason in via_rule if "the host injects" in reason)
    via_rule_undefined = sum(1 for reason in via_rule if "does not define" in reason)
    undefined_directly = sum(
        1 for reason in reasons if reason.startswith("reads a data document the bundle does not")
    )
    network = sum(1 for reason in reasons if "http.send" in reason)

    assert parameters == 26
    assert injected_directly == 11
    assert via_rule_injected == 24, "the rules a policy evaluates, not the libraries it imports"
    assert undefined_directly + via_rule_undefined == 9
    assert via_rule_undefined == 1
    assert network == 1
    accounted = (
        parameters
        + injected_directly
        + via_rule_injected
        + undefined_directly
        + via_rule_undefined
        + network
    )
    assert accounted == len(reasons) == 71


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

    root = _pinned_corpus("TRUSTWEAVE_REGO_CORPUS")

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

    assert len(schemas) == 26
    assert len(reads_outside) == 45
    assert len(schemas) + len(reads_outside) == artifact["counts"]["outside"] == 71
    # And the share over artifacts that are actually policies.
    policies = artifact["policies_considered"] - len(schemas)
    assert policies == 160
    assert round(100 * artifact["counts"]["inside"] / policies, 1) == 71.9

    # Two modules are both, and the one an assignment cannot remove is the one reported.
    doubly = [p for p in outside if len(p.get("reasons") or []) > 1]
    both = [p for p in doubly if any("policy schema" in reason for reason in p["reasons"])]
    assert len(both) == 2
    assert all("policy schema" not in p["reason"] for p in both)


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


def test_an_iam_clock_condition_key_is_outside_like_its_xacml_analogue() -> None:
    """This test used to assert that the adapter contained no OUTSIDE branch at all.

    The caveat it pinned said IAM "offers no construct by which a policy reads state the
    evaluator was not handed -- no lookup, no clock call, no external fetch, and every
    condition key travels with the request". That is false of the language: `aws:CurrentTime`,
    `aws:EpochTime`, `aws:TokenIssueTime` and `aws:MultiFactorAuthAge` are resolved from a
    clock, and XACML's adapter routes the analogous designators outside. With no outside
    branch at all, 1,651 of 1,651 inside could not have come out otherwise. The corpus
    contains none of these keys, so the published 100% does not move -- what moves is the
    reason it is allowed to stand.
    """

    def policy(key: str, operator: str = "DateLessThan") -> str:
        return json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "*",
                        "Condition": {operator: {key: "2026-01-01T00:00:00Z"}},
                    }
                ]
            }
        )

    for key in ("aws:CurrentTime", "aws:EpochTime", "aws:TokenIssueTime", "aws:MultiFactorAuthAge"):
        outcome = iam.classify(policy(key))
        assert outcome.verdict == core.OUTSIDE, key
        assert "reads the clock" in outcome.reason
        assert outcome.detail["clock_condition_keys"] == [key]
    # Case is not load-bearing: AWS condition keys are matched case-insensitively.
    assert iam.classify(policy("AWS:CurrentTime")).verdict == core.OUTSIDE


def test_an_iam_condition_key_the_request_carries_stays_inside() -> None:
    """The refusal direction, so the new branch cannot quietly swallow ordinary keys."""

    def policy(key: str) -> str:
        return json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "*",
                        "Condition": {"StringEquals": {key: "x"}},
                    }
                ]
            }
        )

    for key in ("aws:PrincipalTag/Project", "aws:RequestTag/expirationDate", "s3:prefix"):
        assert iam.classify(policy(key)).verdict == core.INSIDE, key


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


def test_the_construct_the_third_party_corpus_exposed_is_absent_from_the_vendor_one() -> None:
    """Why a vendor corpus could not have found this gap.

    `verifyImages` is the whole of the third-party corpus's 12 exclusions, and it appears in
    none of the vendor policies the study measures. An instrument validated only against the
    vendor's corpus would never have been asked the question, which is the argument for
    going and getting policy somebody else wrote.
    """
    root = _pinned_corpus("TRUSTWEAVE_KYVERNO_CORPUS")

    discovered = kyverno.discover(root)
    assert discovered, "the corpus root holds no Kyverno policies"

    using = [
        subject
        for subject, path in discovered
        if "verifyImages" in path.read_text(encoding="utf-8", errors="ignore")
    ]

    assert using == [], f"the vendor corpus does use verifyImages: {using[:3]}"


# --- Azure Policy, and the taxonomy over everything --------------------------------------

azure = _load("fragment_membership_azure")
taxonomy = _load("exclusion_taxonomy")


def test_the_azure_measurement_judges_every_definition_it_can_read() -> None:
    artifact = json.loads(
        (ROOT / "docs" / "fragment-membership-azure-wide-v1.json").read_text("utf-8")
    )

    assert artifact["policies_considered"] == 3769
    assert artifact["counts"] == {"inside": 2137, "outside": 1589, "undetermined": 43}
    subjects = [entry["subject"] for entry in artifact["policies"]]
    assert len(set(subjects)) == len(subjects), "subjects must be unique or policies vanish"


def test_azure_exclusions_split_into_schemas_reads_and_nondeterminism() -> None:
    artifact = json.loads(
        (ROOT / "docs" / "fragment-membership-azure-wide-v1.json").read_text("utf-8")
    )
    outside = [entry for entry in artifact["policies"] if entry["verdict"] == "outside"]

    schemas = [entry for entry in outside if "policy schema" in entry["reason"]]
    runtime = [entry for entry in outside if "runtime state" in entry["reason"]]
    nondeterministic = [
        entry for entry in outside if "not a function of its arguments" in entry["reason"]
    ]

    related = [entry for entry in outside if "related resource exists" in entry["reason"]]

    assert len(related) == 1444
    assert len(schemas) == 112
    # 3 definitions read `reference()`; the other 21 read a property of the object
    # `resourceGroup()` or `subscription()` returns, which is that object's own state.
    assert len(runtime) == 24
    assert len(nondeterministic) == 9
    assert len(related) + len(schemas) + len(runtime) + len(nondeterministic) == len(outside)
    assert len(outside) == 1589


def test_a_clock_read_is_the_same_kind_of_exclusion_in_azure_as_in_rego() -> None:
    """`utcNow()` and `time.now_ns` are one obstruction and carry one name.

    They were two: the Azure adapter pooled `utcNow` with `reference`, so a definition that
    read the clock was reported as reading another resource's runtime state, and the pooled
    taxonomy carried the same obstruction under two headings depending on the language.
    """

    assert "utcNow" in azure.NONDETERMINISTIC_ARM_FUNCTIONS
    assert "newGuid" in azure.NONDETERMINISTIC_ARM_FUNCTIONS
    assert not (azure.NONDETERMINISTIC_ARM_FUNCTIONS & azure.EXTERNAL_ARM_FUNCTIONS)

    clock = azure.classify(
        json.dumps(
            {
                "properties": {
                    "policyRule": {
                        "if": {"field": "tags['expiry']", "less": "[utcNow()]"},
                        "then": {"effect": "deny"},
                    }
                }
            }
        )
    )

    assert clock.verdict == "outside"
    assert "not a function of its arguments" in clock.reason
    assert taxonomy.classify(clock.reason) == "reads evaluation-time state"


def test_every_azure_obstruction_is_recorded_not_only_the_reported_one() -> None:
    """A definition excluded twice over is visible as such, and the totals reconcile.

    The reported reason is the obstruction that survives instantiation, so a parameterised
    definition that also reads runtime state is reported as reading runtime state. Before
    the evidence was recorded unconditionally, its undefaulted parameters were not in the
    artifact at all, and the count of definitions awaiting an assignment could not be
    derived from the measurement it was quoted beside.
    """

    artifact = json.loads(
        (ROOT / "docs" / "fragment-membership-azure-wide-v1.json").read_text("utf-8")
    )
    outside = [entry for entry in artifact["policies"] if entry["verdict"] == "outside"]
    undefaulted = [entry for entry in outside if entry.get("parameters_without_defaults")]
    schemas = [entry for entry in outside if "policy schema" in entry["reason"]]
    doubly = [entry for entry in outside if entry.get("reasons")]

    # Every definition carrying the schema obstruction, judged or not: the 57 whose guard is
    # a program elsewhere still declare parameters, and whether one carries a default is a
    # fact about the document rather than about our ability to read its guard.
    assert len(undefaulted) == 855, "every exclusion carrying the schema obstruction"
    carrying_schema = [
        entry
        for entry in outside
        if "policy schema" in entry["reason"]
        or any("policy schema" in reason for reason in entry.get("reasons") or [])
    ]
    assert carrying_schema == undefaulted
    assert all(len(entry["reasons"]) > 1 for entry in doubly)
    # Most doubly-excluded definitions are schemas reported under a stronger reason, but not
    # all: 3 both turn on a related resource and read `resourcegroup().managedBy`, and neither
    # obstruction is removed by an assignment.
    assert len(doubly) - len(carrying_schema) + len(schemas) == 3


def test_the_copy_judged_is_the_published_built_in_not_the_tutorial_variant() -> None:
    """An identifier can name two different documents, and the choice between them is ours.

    The repository publishes its built-in definitions under `built-in-policies/` and
    `built-in-references/` and ships tutorial and pattern variants elsewhere, and a variant
    may reuse a built-in's identifier on a document stating a different rule. Keying on the
    identifier and keeping the first path visited therefore decides a verdict, and until
    `CANONICAL_DIRECTORIES` existed it was decided by which path sorted first. It is the same
    answer here, because `built-in-policies` happens to sort before `samples`, which is
    exactly why it should not be left to sorting.
    """

    assert azure.CANONICAL_DIRECTORIES == ("built-in-policies", "built-in-references")

    root = Path("root")
    built_in = root / "built-in-policies" / "policyDefinitions" / "General" / "A.json"
    sample = root / "samples" / "built-in-policy" / "a" / "azurepolicy.json"
    pattern = root / "patterns" / "pattern-1.json"

    ordered = sorted([sample, pattern, built_in], key=lambda path: azure._authority(path, root))

    assert ordered[0] == built_in, "the published definition is judged, not a variant of it"
    assert azure._authority(sample, root)[0] == azure._authority(pattern, root)[0]


def test_the_existence_condition_is_a_guard_and_the_deployment_template_is_not() -> None:
    """The two regions an Azure decision is made in, and the one it is not.

    `if` selects resources and `then.details.existenceCondition` decides compliance for the
    `AuditIfNotExists` and `DeployIfNotExists` shapes; `then.details.deployment` is the
    remediation template, which runs after the decision and cannot affect it. Reading
    operators from `if` while scanning the whole `policyRule` for functions was the
    inconsistency: 96 of 99 exclusions for reading another resource's runtime state were
    `reference()` calls in a remediation template, and the existence condition -- deciding
    1,330 definitions -- was never read at all.
    """

    remediation_only = json.dumps(
        {
            "properties": {
                "policyRule": {
                    "if": {"field": "type", "equals": "Microsoft.Storage/storageAccounts"},
                    "then": {
                        "effect": "deployIfNotExists",
                        "details": {
                            "deployment": {
                                "properties": {
                                    "parameters": {
                                        "id": {"value": "[reference('other').outputs.id]"}
                                    }
                                }
                            }
                        },
                    },
                }
            }
        }
    )
    guard_in_existence = json.dumps(
        {
            "properties": {
                "policyRule": {
                    "if": {"field": "type", "equals": "Microsoft.Sql/servers"},
                    "then": {
                        "effect": "auditIfNotExists",
                        "details": {
                            "type": "Microsoft.Sql/servers/auditingSettings",
                            "existenceCondition": {"field": "name", "equals": "default"},
                        },
                    },
                }
            }
        }
    )

    remediation = azure.classify(remediation_only)
    existence = azure.classify(guard_in_existence)

    # A `reference()` reached only by the remediation template decides nothing, so it is not
    # an exclusion at all: the guard here is `if`, and `if` reads the resource and a literal.
    assert remediation.verdict == "inside"
    assert "runtime state of a resource" not in remediation.reason
    # Naming a related resource type is an existence test, and that is an exclusion.
    assert existence.verdict == "outside"
    assert "related resource exists" in existence.reason
    assert existence.detail["related_resource"]["has_existence_condition"] is True
    assert existence.detail["leaf_operators"] == ["equals"], "the existence condition is read"


def test_an_existence_test_over_a_related_resource_is_outside_the_fragment() -> None:
    """Why: the resource under evaluation does not determine whether another one exists.

    `AuditIfNotExists` asks whether a related resource exists satisfying a condition --
    among the subject's children by default, or anywhere in its resource group. The
    evaluator fetches those after `if` has matched; they are not in the request the decision
    is about. That is Gatekeeper's injected inventory in Azure's clothing, and the corpus
    makes the point plainly: one definition's compliance turns on whether a Security Center
    assessment result exists for the app, which is another service's output entirely.
    """

    artifact = json.loads(
        (ROOT / "docs" / "fragment-membership-azure-wide-v1.json").read_text("utf-8")
    )
    related = [
        entry
        for entry in artifact["policies"]
        if "related resource exists" in entry.get("reason", "")
    ]

    assert len(related) == 1444
    assert all(entry["verdict"] == "outside" for entry in related)
    scopes = {str(entry["related_resource"]["scope"]).lower() for entry in related}
    assert scopes <= {"resource", "resourcegroup", "subscription"}, scopes
    with_condition = [
        entry for entry in related if entry["related_resource"]["has_existence_condition"]
    ]
    assert len(with_condition) == 1330
    assert taxonomy.classify(related[0]["reason"]) == "the subject does not determine the guard"


def test_azure_membership_follows_the_operator_family() -> None:
    """The third language where the family is the right unit, after XACML and IAM."""

    for operator in ("equals", "Like", "notIn", "greaterOrEquals", "exists", "notequals"):
        assert operator.lower() in azure.FINITELY_REFINING_OPERATORS, operator


def test_azure_reads_a_parameterised_definition_with_defaults_as_a_policy() -> None:
    """The distinction Gatekeeper could not show: defaults are an instantiation."""

    with_defaults = {
        "properties": {
            "parameters": {"effect": {"type": "String", "defaultValue": "Audit"}},
            "policyRule": {
                "if": {"field": "type", "equals": "Microsoft.Compute/virtualMachines"},
                "then": {"effect": "[parameters('effect')]"},
            },
        }
    }
    without = json.loads(json.dumps(with_defaults))
    del without["properties"]["parameters"]["effect"]["defaultValue"]

    assert azure.classify(json.dumps(with_defaults)).verdict == core.INSIDE
    outcome = azure.classify(json.dumps(without))
    assert outcome.verdict == core.OUTSIDE
    assert "policy schema" in outcome.reason


def test_azure_reference_is_a_lookup_but_subscription_is_ambient() -> None:
    """`reference()` fetches another resource; `subscription()` is handed to the evaluator."""

    def definition(expression: str) -> str:
        return json.dumps(
            {
                "properties": {
                    "policyRule": {
                        "if": {"value": expression, "equals": "x"},
                        "then": {"effect": "audit"},
                    }
                }
            }
        )

    assert azure.classify(definition("[reference('r').x]")).verdict == core.OUTSIDE
    # These two were pinned INSIDE on the ground that an ambient call is "handed to the
    # evaluator". The criterion the taxonomy actually states is whether the subject determines
    # the guard, and a subscription's display name and a resource group's location are the
    # second object's own state -- exactly what `reference()` is excluded for.
    assert azure.classify(definition("[subscription().displayName]")).verdict == core.OUTSIDE
    assert azure.classify(definition("[resourceGroup().location]")).verdict == core.OUTSIDE
    # The segments of the resource's own id stay inside, which is what keeps the branch narrow.
    assert azure.classify(definition("[resourceGroup().name]")).verdict == core.INSIDE
    assert azure.classify(definition("[subscription().subscriptionId]")).verdict == core.INSIDE


def test_azure_does_not_read_prose_inside_a_string_literal_as_a_function_call() -> None:
    """One built-in says "API Management services (microsoft.apimanagement/service)"."""

    definition = json.dumps(
        {
            "properties": {
                "policyRule": {
                    "if": {"field": "type", "equals": "Microsoft.ApiManagement/service"},
                    "then": {
                        "effect": "audit",
                        "details": {
                            "message": "[concat('for type API Management services "
                            "(microsoft.apimanagement/service), name ', parameters('n'))]"
                        },
                    },
                },
                "parameters": {"n": {"type": "String", "defaultValue": "x"}},
            }
        }
    )

    outcome = azure.classify(definition)

    assert outcome.verdict == core.INSIDE
    assert "services" not in outcome.detail["arm_functions"]


def test_the_corpus_supplies_the_bindings_the_schema_verdict_presumes() -> None:
    """Calling an artifact a schema is only worth doing if the instantiation exists.

    For Gatekeeper and Config Validator the corpus ships a Constraint per template. Azure's
    equivalent is an initiative that includes the definition and binds its parameters, and
    the interesting half of the question is whether it binds the ones that had no default --
    an initiative supplying some other parameter would leave the definition just as far from
    being a policy. It does: every schema an initiative parameterises at all, it completes.
    """

    bindings = json.loads((ROOT / "docs" / "azure-initiative-bindings-v1.json").read_text("utf-8"))
    membership = json.loads(
        (ROOT / "docs" / "fragment-membership-azure-wide-v1.json").read_text("utf-8")
    )
    # Selected by the evidence, not the reported reason: a definition that is a schema and
    # also tests a related resource reports the second, because an assignment removes only
    # the first, so the reason string would have found 120 of the 855.
    schemas = [
        entry for entry in membership["policies"] if entry.get("parameters_without_defaults")
    ]

    assert bindings["schemas"] == len(schemas) == 855
    assert bindings["schemas_an_initiative_completes"] == 555
    assert (
        bindings["schemas_an_initiative_completes"]
        == (bindings["schemas_an_initiative_parameterises"])
    ), "a partial binding would leave the definition a schema still"
    assert len(bindings["schemas_left_uninstantiated"]) == bindings["schemas"] - 555
    assert bindings["initiatives_read"] == 267


def test_the_exclusion_taxonomy_is_exhaustive_over_every_corpus() -> None:
    """The claim worth having, and the instrument can refute it."""

    findings = taxonomy.measure(ROOT / "docs")

    assert findings["taxonomy_is_exhaustive"], findings["exclusions_unclassified"]
    assert findings["exclusions_unclassified"] == {}
    assert findings["corpora"] == 8
    assert findings["artifacts_considered"] == 7008
    assert findings["artifacts_inside"] == 5175
    assert findings["exclusions_by_kind"] == {
        "not a policy": 916,
        "the subject does not determine the guard": 854,
        "reads evaluation-time state": 20,
    }
    assert sum(findings["exclusions_by_kind"].values()) == findings["exclusions"] == 1790


def test_the_taxonomy_counts_over_every_obstruction_not_the_reported_one() -> None:
    """Otherwise the size of a row depends on which other obstruction outranked it.

    A verdict reports the obstruction an assignment cannot remove, so a parameterised
    definition that also tests a related resource reports the test. Counting by the reported
    reason made the "not a policy" row move by 735 Azure definitions when a second guard
    region was read for the first time -- without one artifact changing its schema status.
    """

    reported_schema = {"reason": "is a policy schema rather than a policy: no default for x"}
    reported_read = {
        "reason": "the decision turns on whether a related resource exists, which the "
        "resource under evaluation does not determine",
        "reasons": [
            "the decision turns on whether a related resource exists, which the resource "
            "under evaluation does not determine",
            "is a policy schema rather than a policy: no default for x",
        ],
    }
    read_only = {"reason": "reads a document the host injects: data.inventory"}

    assert taxonomy.kind_of(reported_schema) == "not a policy"
    assert taxonomy.kind_of(reported_read) == "not a policy", "a schema is not a policy"
    assert taxonomy.classify(reported_read["reason"]) == "the subject does not determine the guard"
    assert taxonomy.kind_of(read_only) == "the subject does not determine the guard"

    # And over the corpus: the row equals the artifacts carrying the schema obstruction.
    artifact = json.loads(
        (ROOT / "docs" / "fragment-membership-azure-wide-v1.json").read_text("utf-8")
    )
    carrying = sum(1 for entry in artifact["policies"] if entry.get("parameters_without_defaults"))
    findings = taxonomy.measure(ROOT / "docs")
    azure_row = next(row for row in findings["rows"] if row["corpus"] == "Azure Policy")

    # The two agree. They did not: 14 definitions that delegate their guard returned
    # UNDETERMINED before the schema reason was reached, so they carried the evidence of being
    # schemas while sitting in the policy denominator. Being a schema decides it, so they are
    # judged `outside` and the row is the whole population.
    assert azure_row["exclusions_by_kind"]["not a policy"] == 855
    assert carrying == 855


def test_the_committed_taxonomy_artifact_matches_a_fresh_computation() -> None:
    committed = json.loads((ROOT / "docs" / "exclusion-taxonomy-v1.json").read_text("utf-8"))
    fresh = taxonomy.measure(ROOT / "docs")

    assert committed == fresh


def test_the_only_refusals_are_the_delegated_azure_guards() -> None:
    """A refusal has to be accounted for, or a share stops being a verdict on a whole corpus.

    Seven of the eight corpora leave nothing undetermined. Azure leaves 43, all of them
    definitions that name a Gatekeeper policy program at a URL instead of stating a
    condition: their guard is not in the artifact, and an offline procedure has nothing to
    read. That is the one place the answer is bounded by the instrument rather than by the
    criterion, and it is reported rather than resolved by guessing.

    There were 57. The other 14 declare a parameter with no default, and being a schema
    decides an artifact before its guard has to be read at all.
    """

    findings = taxonomy.measure(ROOT / "docs")
    azure = json.loads(
        (ROOT / "docs" / "fragment-membership-azure-wide-v1.json").read_text("utf-8")
    )

    for row in findings["rows"]:
        expected = 43 if row["corpus"] == "Azure Policy" else 0
        assert row["undetermined"] == expected, row["corpus"]

    unjudged = [entry for entry in azure["policies"] if entry["verdict"] == "undetermined"]
    assert len(unjudged) == 43
    assert all(entry.get("delegates_guard_to") for entry in unjudged)
    assert all("does not contain" in entry["reason"] for entry in unjudged)
    # 42 name the program by URL and 1 carries it inline; either way the location is recorded,
    # so the refusal can be lifted by fetching rather than by re-deriving anything.
    by_url = [
        entry for entry in unjudged if str(entry.get("guard_source", "")).startswith("https://")
    ]
    inline = [entry for entry in unjudged if entry["delegates_guard_to"] == ["constraintTemplate"]]

    assert len(by_url) == 42
    assert len(inline) == 1
    assert len(by_url) + len(inline) == len(unjudged)


# --- What exhaustive coverage costs -----------------------------------------------------

cost = _load("coverage_cost")


def test_a_prefix_pattern_group_admits_only_a_chain_of_signatures() -> None:
    """Lemma: n final-wildcard patterns give n+1 signatures, not 2^n.

    A string matches `q*` exactly when `q` prefixes it, and any two prefixes of one string
    are comparable, so the set of prefix patterns a string matches is a chain determined by
    its longest member. Checked here by enumeration rather than trusted, because this is
    the step that took IAM's median from 16,384 cells to 60.
    """
    import itertools

    patterns = ["s3:", "s3:Get", "s3:GetObject", "ec2:"]
    candidates = ["s3:GetObjectAcl", "s3:GetObject", "s3:Get", "s3:PutObject", "ec2:Run", "x"]
    achieved = {
        tuple(candidate.startswith(prefix) for prefix in patterns) for candidate in candidates
    }

    assert len(achieved) <= len(patterns) + 1
    # And every achieved signature is a chain: the true positions are nested prefixes.
    for signature in achieved:
        true_prefixes = [p for p, held in zip(patterns, signature, strict=True) if held]
        for left, right in itertools.combinations(true_prefixes, 2):
            assert left.startswith(right) or right.startswith(left), (left, right)


def test_literals_are_counted_as_mutually_exclusive() -> None:
    """78.9% of IAM's action and resource entries are literals, and they cannot overlap."""

    assert cost.pattern_kind("s3:GetObject") == "literal"
    assert cost.pattern_kind("s3:Get*") == "prefix"
    assert cost.pattern_kind("s3:*Object") == "wildcard"
    assert cost.pattern_kind("*") == "everything"

    # Ten literals on one component: eleven classes, not 1024.
    groups = {"Action": ["literal"] * 10}
    assert cost.cells_from_groups(groups, frozenset()) == 11
    # Ten prefixes: eleven as well, by the lemma above.
    assert cost.cells_from_groups({"Action": ["prefix"] * 10}, frozenset()) == 11
    # Ten interior wildcards: the exponential is unavoidable.
    assert cost.cells_from_groups({"Action": ["wildcard"] * 10}, frozenset()) == 1024
    # `*` alone splits nothing.
    assert cost.cells_from_groups({"Action": ["everything"]}, frozenset()) == 1


def test_the_cost_artifact_is_marked_withdrawn_rather_than_quoted() -> None:
    """This test used to assert the medians 4 and 60 as findings worth publishing.

    They rested on a grouping rule that counted `in`, `notin`, `containsKey` and
    `notContainsKey` as holding of at most one value each, so on a component carrying two of
    them the count was an under-estimate -- the direction the docstring promised was safe.
    The claim is withdrawn, so what the artifact owes a reader is the notice, not the numbers.
    """

    findings = json.loads((ROOT / "docs" / "coverage-cost-v1.json").read_text("utf-8"))

    notice = findings["invalidated"]
    assert notice["withdrawn"]
    # Both counterexamples the withdrawal rests on, with the count each one refutes.
    reported = {entry["reported"] for entry in notice["counterexamples"]}
    realisable = {entry["realisable_signatures"] for entry in notice["counterexamples"]}
    assert reported == {3} and realisable == {4}
    assert len(notice["counterexamples"]) == 2
    assert "IAM" in notice["same_defect_in_iam"] or "iam" in notice["same_defect_in_iam"]


def test_the_cost_measurement_covers_exactly_the_policies_judged_inside() -> None:
    """A cost distribution over more definitions than are inside is a distribution of what.

    This corpus reuses a definition name across directories. The measurement walked
    (name, path) pairs and so measured seven definitions twice, leaving a denominator
    larger than the inside set it claimed to describe.
    """

    cost_artifact = json.loads((ROOT / "docs" / "coverage-cost-v1.json").read_text("utf-8"))
    for ecosystem, stem in (
        ("azure", "fragment-membership-azure-wide-v1"),
        ("iam", "fragment-membership-iam-wide-v1"),
    ):
        membership = json.loads((ROOT / "docs" / f"{stem}.json").read_text("utf-8"))
        inside = sum(1 for row in membership["policies"] if row["verdict"] == "inside")

        if "invalidated" in cost_artifact:
            # A withdrawn distribution is a record of what was once measured, not a live
            # claim, so it is not held to the membership artifact it no longer describes.
            # Azure moved from 2,150 inside to 2,137 after the adapter corrections, which is
            # a second reason nothing in that artifact should be quoted.
            continue
        assert cost_artifact[ecosystem]["policies"] == inside, ecosystem


def test_the_bound_never_understates_a_group() -> None:
    """Over-estimation is the whole claim, and an empty exclusive set never tested it.

    Every case here passed `frozenset()`, so the `exclusive` branch -- the one that was
    wrong -- never ran. With a real exclusive set the old grouping returned 3 for a pair of
    `in` guards and for a pair of `containsKey` guards, against four realisable signatures,
    and 6 for five `in` guards against a worst case of 32.
    """

    for kinds in (
        ["literal", "prefix"],
        ["literal", "wildcard", "prefix"],
        ["wildcard"] * 3,
        ["literal"] * 4 + ["everything"],
        # The same shapes again, this time through a non-empty exclusive set, plus the
        # operators the withdrawal was filed over.
        ["equals", "equals"],
        ["in", "in"],
        ["containsKey", "containsKey"],
        ["in"] * 5,
        ["equals", "in", "like"],
    ):
        bound = cost.cells_from_groups({"c": kinds}, cost.AZURE_EXCLUSIVE)
        splitting = [k for k in kinds if k != "everything"]
        assert bound <= 2 ** len(splitting) or not splitting
        assert bound >= 1

    # The counterexamples, pinned as values rather than as an inequality.
    assert cost.cells_from_groups({"c": ["in", "in"]}, cost.AZURE_EXCLUSIVE) == 4
    assert cost.cells_from_groups({"c": ["containsKey", "containsKey"]}, cost.AZURE_EXCLUSIVE) == 4
    assert cost.cells_from_groups({"c": ["in"] * 5}, cost.AZURE_EXCLUSIVE) == 32
    # The control from the same probe: `equals` really is one value at most, so `n + 1` holds.
    assert cost.cells_from_groups({"c": ["equals", "equals"]}, cost.AZURE_EXCLUSIVE) == 3


def test_an_iam_condition_over_several_values_is_not_a_single_value_guard() -> None:
    """`iam_guards` recorded one guard per (operator, key) while the value is an array.

    `StringEquals` against `["a", "b"]` is true of either, so two such guards on one key
    realise four signatures. The old grouping called them exclusive and counted three.
    """

    def guards(value: object) -> dict[str, list[str]]:
        return cost.iam_guards(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Condition": {"StringEquals": {"aws:PrincipalTag/x": value}},
                    }
                ]
            }
        )

    assert guards("a")["condition:aws:PrincipalTag/x"] == ["StringEquals"]
    assert guards(["a"])["condition:aws:PrincipalTag/x"] == ["StringEquals"]
    assert guards(["a", "b"])["condition:aws:PrincipalTag/x"] == [cost.MULTI_VALUED]
    single = {"condition:k": ["StringEquals", "StringEquals"]}
    multiple = {"condition:k": [cost.MULTI_VALUED, cost.MULTI_VALUED]}
    assert cost.cells_from_groups(single, cost.IAM_EXCLUSIVE) == 3
    assert cost.cells_from_groups(multiple, cost.IAM_EXCLUSIVE) == 4


def test_a_quotient_past_the_enumeration_limit_keeps_its_exact_size() -> None:
    """The 10**9 cap was published verbatim as the IAM 99th percentile.

    A clamp makes a corpus whose tail is a billion and one whose tail is 10**24 read
    identically, and the artifact then states the instrument's limit as a measurement.
    """

    huge = cost.cells_from_groups({"c": ["wildcard"] * 90}, frozenset())
    assert huge == 2**90
    distribution = cost._distribution([1, 2, huge, huge, huge])
    assert distribution["p99_cells"] == huge
    assert distribution["exceeds_enumeration_limit"] is True
    assert distribution["at_or_above_enumeration_limit"] == 3
    assert cost._distribution([1, 2, 3])["exceeds_enumeration_limit"] is False


def test_the_cost_script_will_not_overwrite_a_withdrawn_artifact(tmp_path: Path) -> None:
    """A plain re-run would have replaced the invalidation notice with fresh numbers.

    That is how a retraction becomes a revision, so the refusal is the point: replacing the
    artifact is allowed, doing it without saying so is not.
    """

    destination = tmp_path / "coverage-cost-v1.json"
    destination.write_text(json.dumps({"invalidated": {"withdrawn": "2026-09-16"}}), "utf-8")
    with pytest.raises(SystemExit) as refusal:
        cost._refuse_to_replace_an_invalidated_artifact(destination)
    assert "--replace-invalidated" in str(refusal.value)

    # A destination that does not exist, or carries no notice, is written without complaint.
    cost._refuse_to_replace_an_invalidated_artifact(tmp_path / "absent.json")
    plain = tmp_path / "plain.json"
    plain.write_text(json.dumps({"schema_version": "v1"}), "utf-8")
    cost._refuse_to_replace_an_invalidated_artifact(plain)


def test_the_iam_cost_measurement_is_checked_against_its_corpus_like_azure_is() -> None:
    """The completeness check existed for Azure only, so IAM drift was invisible."""

    source = (ROOT / "scripts" / "coverage_cost.py").read_text("utf-8")
    assert source.count("the two corpora disagree") == 2
    assert "IAM policies but" in source


# ---------------------------------------------------------------------------------------
# What the differential check against `opa deps` found in the Rego adapter, pinned so that
# none of it comes back. Each case is the shape that was misread, reduced to a fixture.
# ---------------------------------------------------------------------------------------


@opa_required
def test_rego_sees_a_builtin_called_as_a_top_level_statement() -> None:
    """`http.send(req, out)` at the top of a body is a bare terms list, not a `call` node.

    The walker looked for the wrapped form alone, and a published module making network
    calls in exactly this way was recorded inside the fragment.
    """

    outcome = rego.classify(
        "package p\n\n"
        "allow {\n"
        '  req := {"method": "GET", "url": "https://example.invalid"}\n'
        "  http.send(req, out)\n"
        "  out.status_code == 200\n"
        "}\n"
    )
    assert outcome.verdict == core.OUTSIDE
    assert "http.send" in outcome.reason
    assert outcome.detail["evaluation_time_state"] == {"http.send": "the network"}


@opa_required
def test_rego_takes_its_nondeterministic_builtins_from_the_engine() -> None:
    """The engine flags nine; the hand list had five. The engine's list is the one used."""

    engine = rego.nondeterministic_builtins()
    assert engine >= rego.NONDETERMINISTIC_BUILTINS
    assert {"io.jwt.decode_verify", "uuid.rfc4122"} <= engine


@opa_required
def test_rego_reads_a_ref_index_variable_as_computed_not_as_a_key() -> None:
    """`vetter[_].info[result]` indexes by variables; only string parts are static keys."""

    ast = rego.parse("package p\n\nimport data.q.vetter\n\nx[r] {\n  vetter[_].info[r]\n}\n")
    assert ast is not None
    references = rego._every_name_path(ast["rules"][0]["body"])
    assert ["vetter", None, "info", None] in references


@opa_required
def test_rego_input_alias_is_a_read_of_the_request_not_of_data() -> None:
    """`import input as aws` makes `aws.SecurityGroups` the request, not `data.input`."""

    outcome = rego.classify(
        "package p\n\nimport input as aws\n\n"
        "groups[id] = g {\n  aws.SecurityGroups[_] = g\n  g.GroupId = id\n}\n"
    )
    assert outcome.verdict == core.INSIDE


@opa_required
def test_rego_config_validator_parameters_without_a_default_make_a_schema(tmp_path: Path) -> None:
    """Google's templates take parameters through `input.constraint`, not `input.parameters`.

    The first adapter knew only the Gatekeeper plumbing and called every Config Validator
    template a policy. The criterion is the same in both: a parameter read with no default
    in the policy text is what makes a schema.
    """

    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "constraints.rego").write_text(
        "package validator.gcp.lib\n\n"
        "get_constraint_params(constraint) = params {\n  params := constraint.spec.parameters\n}\n"
        "get_default(object, field, _default) = output {\n  object[field]\n"
        "  output = object[field]\n}\n"
        "get_default(object, field, _default) = output {\n  not object[field]\n"
        "  output = _default\n}\n",
        encoding="utf-8",
    )
    validator = tmp_path / "validator"
    validator.mkdir()
    (validator / "raw.rego").write_text(
        "package templates.gcp.RawV1\n\nimport data.validator.gcp.lib as lib\n\n"
        'deny[{"msg": msg}] {\n  constraint := input.constraint\n'
        "  lib.get_constraint_params(constraint, params)\n"
        "  input.asset.location != params.locations[_]\n"
        '  msg := "bad location"\n}\n',
        encoding="utf-8",
    )
    (validator / "defaulted.rego").write_text(
        "package templates.gcp.DefaultedV1\n\nimport data.validator.gcp.lib as lib\n\n"
        'deny[{"msg": msg}] {\n  constraint := input.constraint\n'
        "  lib.get_constraint_params(constraint, params)\n"
        '  mode := lib.get_default(params, "mode", "allowlist")\n'
        '  mode == "denylist"\n'
        '  msg := "denied"\n}\n',
        encoding="utf-8",
    )
    subjects = dict(rego.discover(tmp_path))
    raw = rego.classify(subjects["validator/raw.rego"].read_text(encoding="utf-8"))
    defaulted = rego.classify(subjects["validator/defaulted.rego"].read_text(encoding="utf-8"))

    assert raw.verdict == core.OUTSIDE and "policy schema" in raw.reason
    assert raw.detail["parameter_reads"]["without_default"] == ["locations"]
    assert defaulted.verdict == core.INSIDE
    assert defaulted.detail["parameter_reads"]["with_default"] == ["mode"]


@opa_required
def test_rego_reach_follows_the_rules_a_policy_evaluates_not_its_imports(tmp_path: Path) -> None:
    """One library rule reads the inventory; a policy calling a different one stays inside.

    Import-level propagation excluded every importer of such a library. The engine's own
    dependency analysis disagreed on one published policy, and this is that policy reduced.
    """

    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "openshift.rego").write_text(
        "package lib.openshift\n\n"
        'is_deploymentconfig {\n  input.review.object.kind == "DeploymentConfig"\n}\n\n'
        "disabled_label = label {\n"
        "  ns := data.inventory.cluster.v1.Namespace[input.review.object.metadata.namespace]\n"
        '  label := ns.metadata.labels["disabled"]\n}\n',
        encoding="utf-8",
    )
    policies = tmp_path / "policy"
    policies.mkdir()
    (policies / "calls_request_rule.rego").write_text(
        "package p.a\n\nimport data.lib.openshift\n\n"
        'violation[{"msg": msg}] {\n  openshift.is_deploymentconfig\n  msg := "dc"\n}\n',
        encoding="utf-8",
    )
    (policies / "calls_inventory_rule.rego").write_text(
        "package p.b\n\nimport data.lib.openshift\n\n"
        'violation[{"msg": msg}] {\n  openshift.disabled_label == "x"\n  msg := "off"\n}\n',
        encoding="utf-8",
    )
    subjects = dict(rego.discover(tmp_path))
    request_only = rego.classify(subjects["policy/calls_request_rule.rego"].read_text("utf-8"))
    via_inventory = rego.classify(subjects["policy/calls_inventory_rule.rego"].read_text("utf-8"))

    assert request_only.verdict == core.INSIDE
    assert via_inventory.verdict == core.OUTSIDE
    assert "reaches outside through lib.openshift.disabled_label" in via_inventory.reason
    assert "data.inventory" in via_inventory.reason


@opa_required
def test_rego_reach_resolves_a_package_prefix_indexed_by_a_variable(tmp_path: Path) -> None:
    """`vetter[_].info[r]` evaluates every rule beneath the prefix, including one reading data."""

    audit = tmp_path / "audit"
    audit.mkdir()
    (audit / "audit.rego").write_text(
        "package istio.audit\n\nimport data.istio.audit.vetter\n\n"
        "info[r] {\n  vetter[_].info[r]\n}\n",
        encoding="utf-8",
    )
    (audit / "pods.rego").write_text(
        "package istio.audit.vetter.pods\n\nimport data.kubernetes.pods\n\n"
        'info[r] {\n  pods[_].metadata.name == "x"\n  r := "seen"\n}\n',
        encoding="utf-8",
    )
    subjects = dict(rego.discover(tmp_path))
    outcome = rego.classify(subjects["audit/audit.rego"].read_text(encoding="utf-8"))

    assert outcome.verdict == core.OUTSIDE
    assert "reaches outside through istio.audit.vetter.pods.info" in outcome.reason
    assert "data.kubernetes.pods" in outcome.reason


def test_the_gcp_measurement_applies_the_same_schema_criterion_as_gatekeeper() -> None:
    """One criterion across both Rego corpora: a parameter read with no default is a schema.

    The first GCP measurement reported 85 of 87 inside because the adapter knew only
    Gatekeeper's `input.parameters` and not Config Validator's `input.constraint`. Under the
    one criterion, 31 templates read a parameter they give no default for, 15 read every
    parameter through `lib.get_default` and so carry their own instantiation, and 39 read no
    parameter at all.
    """

    artifact = json.loads(
        (ROOT / "docs" / "fragment-membership-rego-gcp-v1.json").read_text("utf-8")
    )
    assert artifact["counts"] == {"inside": 54, "outside": 33, "undetermined": 0}
    outside = [p for p in artifact["policies"] if p["verdict"] == "outside"]
    schemas = [p for p in outside if "policy schema" in p["reason"]]
    clock = [p for p in outside if "time.now_ns" in p["reason"]]
    assert len(schemas) == 31
    assert len(clock) == 2
    assert all(p["parameter_reads"]["without_default"] for p in schemas)
    inside = [p for p in artifact["policies"] if p["verdict"] == "inside"]
    complete = [
        p
        for p in inside
        if p.get("parameter_reads", {}).get("with_default")
        or p.get("parameter_reads", {}).get("guarded")
    ]
    no_parameter = [p for p in inside if not p.get("parameter_reads")]
    assert len(complete) == 15
    assert len(no_parameter) == 39
    assert not any(p.get("parameter_reads", {}).get("without_default") for p in inside)


# ---------------------------------------------------------------------------------------
# The adapter corrections of the membership audit, each pinned to the shape that was
# misread. Every one of them pulled artifacts *into* the fragment, which is the direction
# the "refuses rather than guesses" contract exists to prevent.
# ---------------------------------------------------------------------------------------


def test_xacml_does_not_read_a_commented_out_condition() -> None:
    """Two conformance policies were excluded for a function only their comments name.

    `PREDICATE_ID` ran over the raw document while guard elements and well-formedness came
    from the parsed tree, which drops comments. `IIF301_FIXED_NO_XPATH` and
    `IIF310_FIXED_NO_XPATH` have their entire `<Condition>` commented out under the note
    "XPath support is optional in XACML 3.0 therefore removed here", and both shipped
    OUTSIDE with `external_functions: ["xpath-node-count"]`.
    """

    live = (
        '<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" '
        'PolicyId="p" RuleCombiningAlgId="a"><Target/>'
        '<Rule RuleId="r" Effect="Permit"><Condition>'
        '<Apply FunctionId="urn:oasis:names:tc:xacml:3.0:function:xpath-node-count"/>'
        "</Condition></Rule></Policy>"
    )
    commented = live.replace(
        '<Condition><Apply FunctionId="urn:oasis:names:tc:xacml:3.0:function:'
        'xpath-node-count"/></Condition>',
        "<!-- XPath support is optional in XACML 3.0 therefore removed here"
        '<Condition><Apply FunctionId="urn:oasis:names:tc:xacml:3.0:function:'
        'xpath-node-count"/></Condition> -->',
    )

    assert xacml.classify(live).verdict == core.OUTSIDE
    outcome = xacml.classify(commented)
    assert outcome.verdict == core.INSIDE
    assert outcome.detail["functions"] == []


def test_xacml_does_not_admit_a_vendor_function_on_a_family_name_coincidence() -> None:
    """The URN was reduced to its last colon segment before anything looked at it.

    No acceptance path inspected the namespace, so `urn:acme:pdp:function:consult-oracle:equal`
    was admitted as finitely refining by the family suffix rule -- the guess the adapter's own
    `EXTERNAL_FUNCTIONS` mechanism exists to make impossible. The leak is one-directional: a
    coincidence can only pull a vendor URN into INSIDE.
    """

    # A bare local name has no namespace to check, and keeps the family rule.
    assert xacml.is_finitely_refining("integer-greater-than")
    assert xacml.is_finitely_refining("urn:oasis:names:tc:xacml:1.0:function:integer-greater-than")

    assert not xacml.is_finitely_refining("urn:acme:pdp:function:ask-the-network:greater-than")
    assert not xacml.is_finitely_refining("urn:acme:pdp:function:query-ldap:is-in")

    # The explicit lists still admit by local name, which is why the corpus's one vendor
    # `...:test-extensible-value:equal` document does not move.
    assert xacml.is_finitely_refining("urn:ow2:authzforce:feature:pdp:function:x:equal")


def test_azure_reads_the_property_and_not_the_ambient_call_name() -> None:
    """`PURE_ARM_FUNCTIONS` listed the bare call, so every property read came with it."""

    reads = azure.ambient_property_reads({"value": "[resourcegroup().managedBy]", "equals": "x"})
    assert reads == {"resourcegroup().managedBy"}
    assert azure.ambient_property_reads({"value": "[resourceGroup().name]", "equals": "x"}) == set()
    assert (
        azure.ambient_property_reads({"value": "[subscription().subscriptionId]", "equals": "x"})
        == set()
    )
    # A bare call passed to another function reads no property and stays pure.
    assert azure.ambient_property_reads({"value": "[concat(resourceGroup())]"}) == set()


def test_an_azure_schema_that_delegates_its_guard_is_still_not_a_policy() -> None:
    """Being a schema decides an artifact before its guard has to be readable.

    The delegation branch returned UNDETERMINED before the schema reason was reached, so 14
    definitions that are schemas by this adapter's own test sat in the policy denominator of
    the pooled share while the artifact recorded the evidence that they were not policies.
    """

    def definition(with_default: bool) -> str:
        parameter = (
            {"type": "String"} if not with_default else {"type": "String", "defaultValue": "x"}
        )
        return json.dumps(
            {
                "properties": {
                    "parameters": {"limit": parameter},
                    "policyRule": {
                        "if": {"field": "type", "equals": "Microsoft.Kubernetes/connectedClusters"},
                        "then": {
                            "effect": "audit",
                            "details": {
                                "templateInfo": {
                                    "sourceType": "PublicURL",
                                    "url": "https://store.policy.core.windows.net/t.yaml",
                                }
                            },
                        },
                    },
                }
            }
        )

    schema = azure.classify(definition(with_default=False))
    assert schema.verdict == core.OUTSIDE
    assert "policy schema" in schema.reason
    # The delegation is still recorded, so the refusal can be lifted by fetching.
    assert schema.detail["delegates_guard_to"] == ["templateInfo"]
    assert taxonomy.classify(schema.reason) == "not a policy"

    # A definition whose parameters all carry defaults is still refused: its guard really is
    # somewhere else, and that is not something being a policy makes readable.
    delegating = azure.classify(definition(with_default=True))
    assert delegating.verdict == core.UNDETERMINED
    assert "does not contain" in delegating.reason


def test_the_cedar_archive_row_is_measured_and_kept_out_of_the_published_row() -> None:
    """22 tracked `.cedar` files were the whole "wide" Cedar row; 7,497 sat in a tarball.

    The adapter had no wide walk at all, so `fragment_membership.py`'s
    `getattr(adapter, "discover_wide", adapter.discover)` made the wide row the narrow one.
    The archive is fuzzer output, so it is measured under its own scope rather than folded
    into the corpus row, and the published row is unchanged.
    """

    published = json.loads(
        (ROOT / "docs" / "fragment-membership-cedar-wide-v1.json").read_text("utf-8")
    )
    archive = json.loads(
        (ROOT / "docs" / "fragment-membership-cedar-archive-v1.json").read_text("utf-8")
    )

    assert published["corpus_scope"] == "wide"
    assert published["policies_considered"] == 22
    assert archive["corpus_scope"] == "archive"
    assert archive["policies_considered"] == 7497
    assert archive["counts"] == {"inside": 6541, "outside": 0, "undetermined": 956}
    assert archive["corpus"][0]["commit"] == published["corpus"][0]["commit"]
    (source,) = archive["archives"]
    assert source["archive"] == "corpus-tests.tar.gz"
    assert source["cedar_members"] == 7497
    assert source["sha256"] == ("d8fd6e25ac1816a9db70c8ed2194101dbceabcede1da5599700660ad28bde5c4")
    # The claim the archive refutes: the OLD draft said the refusal path "is exercised on
    # synthetic inputs because the corpus never triggers it".
    assert archive["counts"]["undetermined"] > 0


def test_an_archive_walk_is_asked_for_and_never_substituted() -> None:
    """A `getattr` fallback is how the Cedar row came to mean something nobody chose."""

    assert core.discovery_for(cedar, wide=True) is cedar.discover
    assert core.discovery_for(cedar, wide=False, archive=True) is cedar.discover_archive
    with pytest.raises(SystemExit, match="no archive"):
        core.discovery_for(iam, wide=False, archive=True)
