"""Declaration drift, coverage arithmetic, and the draft's review instructions.

Mutation testing found these unasserted: the rename heuristic's thresholds, the coverage
basis-point arithmetic, the `coverage_status` value, and every line of the guidance that
tells a reviewer the draft is not a manifest. A change to any of them passed the suite.

The guidance is asserted as a whole list rather than line by line. It is contract text a
reviewer reads before trusting a draft, so changing it should be a deliberate edit to one
test rather than something that slips through.
"""

from __future__ import annotations

from trustweave.code_analysis import DiscoveredTool
from trustweave.code_discovery import _drift, _manifest_draft
from trustweave.models import parse_manifest


def _tool(name: str) -> DiscoveredTool:
    return DiscoveredTool(name, "langchain_tool_decorator", "tools.py", 1)


def _manifest(*names: str):
    return parse_manifest(
        {
            "schema_version": "trustweave.dev/v1alpha1",
            "name": "agent",
            "description": "An agent used to exercise declaration drift.",
            "sources": [
                {
                    "name": "inbox",
                    "trust": "untrusted",
                    "data_classification": "internal",
                    "description": "A declared ingress point for the drift fixture.",
                }
            ],
            "tools": [
                {
                    "name": name,
                    "action_class": "read",
                    "capabilities": ["knowledge-base.read"],
                    "description": f"Declared tool {name} for the drift fixture.",
                }
                for name in names
            ],
            "flows": [
                {
                    "source": "inbox",
                    "tool": name,
                    "purpose": f"A declared path reaching {name} in the drift fixture.",
                }
                for name in names
            ],
        }
    )


# ---------------------------------------------------------------------------------------
# Without a manifest there is nothing to measure, and it must say so
# ---------------------------------------------------------------------------------------


def test_no_manifest_reports_that_none_was_supplied() -> None:
    assert _drift([_tool("probe")], None) == {
        "manifest_supplied": False,
        "coverage_status": "not_applicable",
    }


def test_no_discovered_tools_leaves_coverage_unmeasured() -> None:
    """Dividing by zero tools would be a crash; claiming 100% would be a lie."""

    drift = _drift([], _manifest("probe"))

    assert drift["coverage_status"] == "not_applicable"
    assert "declaration_coverage_basis_points" not in drift
    assert drift["manifest_supplied"] is True


# ---------------------------------------------------------------------------------------
# Coverage is exact integer arithmetic, reported both ways
# ---------------------------------------------------------------------------------------


def test_coverage_is_floor_division_into_basis_points() -> None:
    """One of three matched is 33.33%, not 33.34% and not a float."""

    drift = _drift([_tool("a"), _tool("b"), _tool("c")], _manifest("a"))

    assert drift["declaration_coverage_basis_points"] == 3333
    assert isinstance(drift["declaration_coverage_basis_points"], int)
    assert drift["declaration_coverage_percent"] == "33.33"
    assert drift["coverage_status"] == "measured"


def test_full_coverage_reports_exactly_ten_thousand_basis_points() -> None:
    drift = _drift([_tool("a"), _tool("b")], _manifest("a", "b"))

    assert drift["declaration_coverage_basis_points"] == 10000
    assert drift["declaration_coverage_percent"] == "100.00"
    assert drift["tools_matched"] == 2


def test_drift_is_reported_in_both_directions() -> None:
    drift = _drift([_tool("found_only")], _manifest("declared_only"))

    assert drift["missing_from_manifest"] == ["found_only"]
    assert drift["declared_not_found_in_code"] == ["declared_only"]
    assert drift["tools_declared"] == 1
    assert drift["tools_discovered"] == 1
    assert drift["tools_matched"] == 0


# ---------------------------------------------------------------------------------------
# The rename heuristic, at its threshold
# ---------------------------------------------------------------------------------------


def test_a_near_identical_name_is_offered_as_a_probable_rename() -> None:
    drift = _drift([_tool("send_receipt")], _manifest("send_reciept"))

    assert drift["probable_renames"] == [{"declared": "send_reciept", "discovered": "send_receipt"}]


def test_an_unrelated_name_is_not_offered_as_a_rename() -> None:
    """Below the similarity cutoff, so guessing a rename would invent a relationship."""

    drift = _drift([_tool("delete_everything")], _manifest("probe"))

    assert drift["probable_renames"] == []


def test_only_the_single_closest_candidate_is_offered() -> None:
    """`n=1`: offering several turns a hint into a puzzle."""

    drift = _drift([_tool("send_receipt"), _tool("send_receipts")], _manifest("send_reciept"))

    assert len(drift["probable_renames"]) == 1


def test_a_matched_tool_produces_no_rename_suggestion() -> None:
    assert _drift([_tool("probe")], _manifest("probe"))["probable_renames"] == []


# ---------------------------------------------------------------------------------------
# The draft says, in words, that it is not a manifest
# ---------------------------------------------------------------------------------------


def test_the_draft_carries_its_review_instructions_verbatim() -> None:
    """This text is what stops a draft being used as a declaration. It is contract."""

    assert _manifest_draft([])["review_required"] == [
        "Assign every source trust: trusted, untrusted, or conditional. "
        "TrustWeave emitted unknown and did not guess.",
        "Confirm or correct every proposed action_class, and resolve every unknown.",
        "Add capabilities, data classifications, and flows before using this as a manifest.",
    ]


def test_the_draft_source_says_why_its_trust_is_unknown() -> None:
    source = _manifest_draft([])["sources"][0]

    assert source["trust"] == "unknown"
    assert source["description"] == (
        "TrustWeave does not infer trust from code. A reviewer must name every "
        "ingress point and assign its trust."
    )


def test_the_draft_name_and_description_are_placeholders_a_reviewer_must_replace() -> None:
    draft = _manifest_draft([])

    assert draft["name"] == "REVIEW_REQUIRED_DISCOVERED_AGENT"
    assert draft["description"] == "REVIEW_REQUIRED: describe this agent before using this draft."
    assert draft["sources"][0]["name"] == "REVIEW_REQUIRED_source"
    assert draft["sources"][0]["data_classification"] == "REVIEW_REQUIRED"
