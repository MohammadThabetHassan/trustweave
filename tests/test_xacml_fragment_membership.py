"""Tests for the XACML fragment-membership test.

The instrument decides whether a published policy lies inside the decidable fragment of
docs/DECISION_CLASS_COVERAGE.md. It is the only measurement backing that section, so the
cases it must not get wrong are asserted here rather than left to a corpus run: the two
extraction bugs found while writing it, the refusal behaviour, and the committed figure.

The corpus itself is not in the repository -- it is fetched at the commits the suite
coverage study pins -- so these tests work on transcribed documents and the committed
artifact, and run without a network.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "docs" / "xacml-fragment-membership-v1.json"

_specification = importlib.util.spec_from_file_location(
    "xacml_fragment_membership", ROOT / "scripts" / "xacml_fragment_membership.py"
)
assert _specification and _specification.loader
membership: ModuleType = importlib.util.module_from_spec(_specification)
sys.modules["xacml_fragment_membership"] = membership
_specification.loader.exec_module(membership)

NAMESPACE = 'xmlns:x="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"'


def _policy(inner: str) -> str:
    return f'<?xml version="1.0"?><x:Policy {NAMESPACE} PolicyId="p">{inner}</x:Policy>'


def _target_match(match_id: str) -> str:
    return (
        "<x:Target><x:AnyOf><x:AllOf>"
        f'<x:Match MatchId="urn:oasis:names:tc:xacml:1.0:function:{match_id}">'
        "<x:AttributeValue>medical-record</x:AttributeValue>"
        '<x:AttributeDesignator AttributeId="resource-type"/>'
        "</x:Match></x:AllOf></x:AnyOf></x:Target>"
    )


class TestVerdicts:
    def test_a_target_match_against_a_literal_is_inside(self) -> None:
        verdict, evidence = membership.classify_policy(_policy(_target_match("string-equal")))

        assert verdict == membership.INSIDE
        assert evidence["functions"] == ["string-equal"]

    def test_a_target_predicate_is_seen_even_though_it_is_named_matchid(self) -> None:
        """The first version scanned only FunctionId and so saw no guard here at all.

        That reported a policy whose only guard is a string-equal target as naming no
        function, which is the opposite of the truth about it.
        """

        verdict, evidence = membership.classify_policy(_policy(_target_match("string-equal")))

        assert verdict == membership.INSIDE
        assert evidence["reason"] != "names no function at all"

    def test_selecting_over_request_content_is_outside(self) -> None:
        document = _policy(
            _target_match("string-equal") + '<x:Rule Effect="Permit" RuleId="r"><x:Condition>'
            '<x:Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-equal">'
            '<x:AttributeSelector Path="//md:record/md:patient" DataType="string"/>'
            "</x:Apply></x:Condition></x:Rule>"
        )
        verdict, evidence = membership.classify_policy(document)

        assert verdict == membership.OUTSIDE
        assert "XPath" in evidence["reason"]

    def test_content_selection_outranks_an_otherwise_admissible_guard(self) -> None:
        """A policy is inside only when *every* guard is; one selector is enough."""

        document = _policy(_target_match("string-equal") + "<x:AttributeSelector/>")

        assert membership.classify_policy(document)[0] == membership.OUTSIDE

    def test_an_unrecognised_function_is_undetermined_rather_than_either_verdict(self) -> None:
        verdict, evidence = membership.classify_policy(_policy(_target_match("xpath-node-count")))

        assert verdict == membership.UNDETERMINED
        assert evidence["unrecognised_functions"] == ["xpath-node-count"]

    def test_a_policy_with_no_guard_at_all_is_undetermined(self) -> None:
        assert membership.classify_policy(_policy("<x:Description>none</x:Description>"))[0] == (
            membership.UNDETERMINED
        )

    def test_malformed_xml_is_undetermined_rather_than_crashing(self) -> None:
        verdict, evidence = membership.classify_policy("<x:Policy><unclosed>")

        assert verdict == membership.UNDETERMINED
        assert "well-formed" in evidence["reason"]

    @pytest.mark.parametrize(
        "function",
        ["string-equal", "string-regexp-match", "ip-in-range", "any-of", "string-is-in"],
    )
    def test_each_admitted_function_is_judged_finitely_refining(self, function: str) -> None:
        assert function in membership.FINITELY_REFINING_FUNCTIONS
        assert membership.classify_policy(_policy(_target_match(function)))[0] == (
            membership.INSIDE
        )

    def test_a_regexp_pattern_from_the_policy_is_admitted_with_a_recorded_reason(self) -> None:
        """XML Schema regexp has no backreferences, so the pattern is a regular language."""

        source = (ROOT / "scripts" / "xacml_fragment_membership.py").read_text(encoding="utf-8")

        assert "string-regexp-match" in membership.FINITELY_REFINING_FUNCTIONS
        assert "no backreferences" in source


class TestSubjectNaming:
    def test_the_subject_matches_the_suite_coverage_adapter(self, tmp_path: Path) -> None:
        """The two instruments must name the same policy the same way, or no join works."""

        suite = tmp_path / "basic" / "3" / "policies"
        suite.mkdir(parents=True)
        policy = suite / "TestPolicy_0007.xml"
        policy.write_text(_policy(_target_match("string-equal")), encoding="utf-8")

        assert membership.subject_for(policy) == "basic/3/policy_0007"

    def test_only_numbered_policies_in_a_policies_directory_are_discovered(
        self, tmp_path: Path
    ) -> None:
        policies = tmp_path / "basic" / "3" / "policies"
        policies.mkdir(parents=True)
        (policies / "TestPolicy_0001.xml").write_text("<x/>", encoding="utf-8")
        (policies / "TestPolicy_notanumber.xml").write_text("<x/>", encoding="utf-8")
        elsewhere = tmp_path / "basic" / "3" / "requests"
        elsewhere.mkdir()
        (elsewhere / "TestPolicy_0002.xml").write_text("<x/>", encoding="utf-8")

        found = [path.name for path in membership.discover(tmp_path)]

        assert found == ["TestPolicy_0001.xml"]


@pytest.fixture(scope="module")
def artifact() -> dict:
    return json.loads(ARTIFACT.read_text(encoding="utf-8"))


class TestCommittedArtifact:
    """The figure section 4b of the theory document quotes."""

    def test_every_policy_the_study_measured_is_judged(self, artifact: dict) -> None:
        coverage = json.loads(
            (ROOT / "docs" / "suite-coverage-xacml-v1.json").read_text(encoding="utf-8")
        )
        measured = {subject["subject"] for subject in coverage["subjects"]}
        judged = {entry["subject"] for entry in artifact["policies"]}

        assert judged == measured

    def test_nothing_is_left_undetermined(self, artifact: dict) -> None:
        """A verdict on the whole corpus, not on the part the instrument understood."""

        assert artifact["counts"]["undetermined"] == 0

    def test_the_quoted_figures_hold(self, artifact: dict) -> None:
        assert artifact["counts"]["inside"] == 15
        assert artifact["counts"]["outside"] == 6
        assert artifact["policies_considered"] == 21
        assert artifact["share_inside"] == 0.7143

    def test_every_policy_outside_is_outside_for_the_same_single_reason(
        self, artifact: dict
    ) -> None:
        """The sharp part of the finding: one construct accounts for all of them."""

        reasons = {
            entry["reason"] for entry in artifact["policies"] if entry["verdict"] == "outside"
        }

        assert reasons == {"selects over request content with XPath"}

    def test_the_counts_add_up_to_the_policies_judged(self, artifact: dict) -> None:
        assert sum(artifact["counts"].values()) == artifact["policies_considered"]
