"""The traversal's three continuations, and the warning list it appends to.

`review_declared_chains` walks a declared graph under budgets. Three of its `continue`
statements keep the walk going past something it has finished with -- a state already
seen, a node with nowhere left to go, a path that reached the depth bound. Turning any of
them into `break` ends the whole traversal, which silently discards every sibling branch
still on the stack and produces a clean review of a graph that was never fully walked.
That is the failure the depth bound's own comment describes, so each continuation is
exercised with a branch left to lose.

The warning list is passed by reference into the classification check. Passing nothing in
its place raises only when a declared classification is unrecognised, which no test
supplied.
"""

from __future__ import annotations

from typing import Any

from trustweave.chain import review_declared_chains


def _document(nodes: list[dict[str, Any]], edges: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "schema_version": "trustweave.dev/chain-manifest/v1alpha1",
        "name": "declared-chain",
        "nodes": nodes,
        "edges": edges,
    }


def _finding_ids(review: dict[str, Any]) -> list[str]:
    return [finding["id"] for finding in review["findings"]]


def test_a_node_with_nowhere_left_to_go_does_not_end_the_whole_walk() -> None:
    """The dead end is popped first; the external sink behind it must still be reached.

    On `break` the sink is left on the stack and the review reports no declared path at
    all, which reads as a graph with nothing flowing out of it.
    """

    review = review_declared_chains(
        _document(
            [
                {"id": "source", "kind": "source", "trust": "untrusted"},
                {"id": "deadend", "kind": "tool", "action_class": "read"},
                {"id": "sink", "kind": "sink", "action_class": "external"},
            ],
            [
                {"from": "source", "to": "deadend"},
                {"from": "source", "to": "sink"},
            ],
        )
    )

    assert review["paths"] == [{"identity": ["source", "sink"]}]


def test_a_state_already_seen_is_skipped_without_ending_the_walk() -> None:
    """A duplicated edge offers the same state twice; the repeat is skipped, not fatal."""

    review = review_declared_chains(
        _document(
            [
                {"id": "source", "kind": "source", "trust": "untrusted"},
                {"id": "sink", "kind": "sink", "action_class": "external"},
            ],
            [
                {"from": "source", "to": "sink"},
                {"from": "source", "to": "sink"},
            ],
        )
    )

    assert review["paths"] == [{"identity": ["source", "sink"]}]
    assert "TW-CHAIN-004" not in _finding_ids(review)


def test_a_repeated_state_is_not_counted_against_the_state_budget() -> None:
    """Deduplication is what keeps a duplicated edge from spending budget twice.

    With the state budget set to exactly the two states this graph has, a traversal that
    fails to recognise the repeat spends a third and reports the analysis as incomplete --
    a budget finding on a two-node graph.
    """

    review = review_declared_chains(
        _document(
            [
                {"id": "source", "kind": "source", "trust": "untrusted"},
                {"id": "sink", "kind": "sink", "action_class": "external"},
            ],
            [
                {"from": "source", "to": "sink"},
                {"from": "source", "to": "sink"},
            ],
        ),
        max_states=2,
    )

    assert "TW-CHAIN-004" not in _finding_ids(review)
    assert review["paths"] == [{"identity": ["source", "sink"]}]


def test_a_path_reaching_the_depth_bound_does_not_end_the_whole_walk() -> None:
    """max_depth bounds one path, not the search: the second source must still be walked.

    `beta` sorts after `alpha`, so ending the traversal at the depth bound discards it
    entirely -- the regression the code's own comment records.
    """

    review = review_declared_chains(
        _document(
            [
                {"id": "alpha", "kind": "source", "trust": "untrusted"},
                {"id": "hop", "kind": "tool", "action_class": "read"},
                {"id": "deep", "kind": "sink", "action_class": "external"},
                {"id": "beta", "kind": "source", "trust": "untrusted"},
                {"id": "out", "kind": "sink", "action_class": "external"},
            ],
            [
                {"from": "alpha", "to": "hop"},
                {"from": "hop", "to": "deep"},
                {"from": "beta", "to": "out"},
            ],
        ),
        max_depth=2,
    )

    identities = [entry["identity"] for entry in review["paths"]]
    assert ["beta", "out"] in identities, "the second source was discarded by the depth bound"
    assert "TW-CHAIN-004" in _finding_ids(review), "reaching the bound is still reported"


def test_an_unrecognised_covered_classification_is_reported_as_a_warning() -> None:
    """The warning list is passed into the check by reference and must be appendable."""

    review = review_declared_chains(
        _document(
            [
                {"id": "source", "kind": "source", "trust": "untrusted"},
                {
                    "id": "clean",
                    "kind": "sanitizer",
                    "covers_classifications": ["totally-unrelated-term"],
                },
                {"id": "sink", "kind": "sink", "action_class": "external"},
            ],
            [
                {"from": "source", "to": "clean"},
                {"from": "clean", "to": "sink"},
            ],
        )
    )

    assert len(review["warnings"]) == 1
    assert "'totally-unrelated-term' is not named" in review["warnings"][0]
