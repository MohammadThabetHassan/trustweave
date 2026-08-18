from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.chain import render_chain_review, review_declared_chains
from trustweave.cli import main
from trustweave.models import ValidationError


def _document(nodes: list[dict[str, object]], edges: list[dict[str, str]]) -> dict[str, object]:
    return {
        "schema_version": "trustweave.dev/chain-manifest/v1alpha1",
        "name": "declared-chain",
        "nodes": nodes,
        "edges": edges,
    }


def _unsafe_nodes() -> list[dict[str, object]]:
    return [
        {"id": "inbox", "kind": "source", "trust": "untrusted"},
        {"id": "records", "kind": "data", "classification": "confidential"},
        {"id": "email", "kind": "tool", "action_class": "external"},
    ]


def test_chain_manifest_rejects_incompatible_node_fields() -> None:
    document = _document(_unsafe_nodes(), [])
    source = document["nodes"][0]
    assert isinstance(source, dict)
    source["action_class"] = "external"
    with pytest.raises(ValidationError, match="not valid for source"):
        review_declared_chains(document)

    document = _document(_unsafe_nodes(), [])
    data = document["nodes"][1]
    assert isinstance(data, dict)
    data.pop("classification")
    with pytest.raises(ValidationError, match="classification is required"):
        review_declared_chains(document)


def test_chain_diamond_preserves_distinct_declared_paths() -> None:
    document = _document(
        [
            {"id": "source", "kind": "source", "trust": "untrusted"},
            {"id": "left", "kind": "tool", "action_class": "read"},
            {"id": "right", "kind": "tool", "action_class": "read"},
            {"id": "sink", "kind": "sink", "action_class": "external"},
        ],
        [
            {"from": "source", "to": "left"},
            {"from": "source", "to": "right"},
            {"from": "left", "to": "sink"},
            {"from": "right", "to": "sink"},
        ],
    )

    review = review_declared_chains(document)

    assert review["paths"] == [
        {"identity": ["source", "left", "sink"]},
        {"identity": ["source", "right", "sink"]},
    ]


def test_approval_does_not_cover_later_sensitive_acquisition() -> None:
    document = _document(
        [
            {"id": "source", "kind": "source", "trust": "untrusted"},
            {"id": "confidential", "kind": "data", "classification": "confidential"},
            {"id": "approval", "kind": "approval", "fail_closed": True},
            {"id": "restricted", "kind": "data", "classification": "restricted"},
            {"id": "sink", "kind": "sink", "action_class": "external"},
        ],
        [
            {"from": "source", "to": "confidential"},
            {"from": "confidential", "to": "approval"},
            {"from": "approval", "to": "restricted"},
            {"from": "restricted", "to": "sink"},
        ],
    )

    review = review_declared_chains(document)

    assert any(finding["id"] == "TW-CHAIN-002" for finding in review["findings"])


def test_checked_in_safe_sanitized_chain_example_has_no_review_findings() -> None:
    example_path = (
        Path(__file__).resolve().parents[1]
        / "examples"
        / "chains"
        / "safe-sanitized-external.chain.json"
    )
    review = review_declared_chains(
        json.loads(example_path.read_text(encoding="utf-8")),
        generated_at="2026-08-13T00:00:00+00:00",
    )

    assert review["findings"] == []
    assert review["paths"] == [
        {
            "identity": [
                "customer-request",
                "customer-record",
                "declared-redactor",
                "external-notification",
            ]
        }
    ]


def test_chain_review_reports_only_explicitly_declared_unsafe_path() -> None:
    review = review_declared_chains(
        _document(
            _unsafe_nodes(),
            [{"from": "inbox", "to": "records"}, {"from": "records", "to": "email"}],
        ),
        generated_at="2026-08-13T00:00:00+00:00",
    )
    assert [item["id"] for item in review["findings"]] == ["TW-CHAIN-001", "TW-CHAIN-002"]
    assert review["findings"][0]["subject"] == {"path": ["inbox", "records", "email"]}


def test_chain_review_respects_declared_fail_closed_approval_and_reports_incomplete_sanitizer() -> (
    None
):
    nodes = _unsafe_nodes() + [
        {"id": "approval", "kind": "approval", "fail_closed": True},
        {"id": "redactor", "kind": "sanitizer", "covers_classifications": ["internal"]},
    ]
    review = review_declared_chains(
        _document(
            nodes,
            [
                {"from": "inbox", "to": "records"},
                {"from": "records", "to": "approval"},
                {"from": "approval", "to": "redactor"},
                {"from": "redactor", "to": "email"},
            ],
        ),
        generated_at="2026-08-13T00:00:00+00:00",
    )
    assert [item["id"] for item in review["findings"]] == ["TW-CHAIN-001", "TW-CHAIN-003"]
    sanitizer_finding = review["findings"][1]
    assert sanitizer_finding == {
        "id": "TW-CHAIN-003",
        "severity": "medium",
        "evidence_kind": "declared_chain_configuration",
        "message": (
            "A declared sanitizer does not list coverage for every propagated sensitive "
            "classification."
        ),
        "subject": {"path": ["inbox", "records", "approval", "redactor", "email"]},
        "properties": {"classifications": ["confidential"], "sanitizer": "redactor"},
        "location": {"path_identity": "inbox -> records -> approval -> redactor -> email"},
    }


def test_chain_review_rejects_every_non_positive_traversal_budget() -> None:
    """All declared traversal budgets are strictly positive before graph parsing begins."""

    document = _document(_unsafe_nodes(), [])
    for budget_name in ("max_nodes", "max_paths", "max_edges", "max_depth", "max_states"):
        with pytest.raises(ValidationError) as error:
            review_declared_chains(document, **{budget_name: 0})
        assert str(error.value) == "chain analysis budgets must be positive"


def test_chain_check_cli_writes_local_json_and_markdown(tmp_path: Path) -> None:
    input_path = tmp_path / "chain.json"
    input_path.write_text(
        json.dumps(
            _document(
                _unsafe_nodes(),
                [{"from": "inbox", "to": "records"}, {"from": "records", "to": "email"}],
            )
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "artifacts"
    assert main(["chain-check", "--input", str(input_path), "--output-dir", str(output_dir)]) == 0
    assert (output_dir / "chain-review.json").is_file()
    assert "TW-CHAIN-001" in (output_dir / "chain-review.md").read_text(encoding="utf-8")


def test_chain_traversal_terminates_at_declared_external_action() -> None:
    review = review_declared_chains(
        _document(
            _unsafe_nodes(),
            [
                {"from": "inbox", "to": "records"},
                {"from": "records", "to": "email"},
                {"from": "email", "to": "records"},
            ],
        ),
        generated_at="2026-08-13T00:00:00+00:00",
    )
    assert review["paths"] == [{"identity": ["inbox", "records", "email"]}]


def test_chain_review_tracks_sanitized_classifications_as_propagated_state() -> None:
    nodes = _unsafe_nodes() + [
        {"id": "redactor", "kind": "sanitizer", "covers_classifications": ["confidential"]}
    ]
    review = review_declared_chains(
        _document(
            nodes,
            [
                {"from": "inbox", "to": "records"},
                {"from": "records", "to": "redactor"},
                {"from": "redactor", "to": "email"},
            ],
        ),
        generated_at="2026-08-13T00:00:00+00:00",
    )

    assert review["paths"] == [{"identity": ["inbox", "records", "redactor", "email"]}]
    assert review["findings"] == []


def test_chain_review_enforces_edge_depth_and_state_budgets() -> None:
    document = _document(
        _unsafe_nodes(),
        [{"from": "inbox", "to": "records"}, {"from": "records", "to": "email"}],
    )
    for budget in ({"max_edges": 1}, {"max_depth": 2}, {"max_states": 2}):
        review = review_declared_chains(
            document,
            generated_at="2026-08-13T00:00:00+00:00",
            **budget,
        )
        finding = review["findings"][0]
        assert finding["id"] == "TW-CHAIN-004"
        assert finding["properties"]["budget"] in {"max_edges", "max_depth", "max_states"}


def test_chain_review_handles_cycles_and_reports_budget_limits() -> None:
    cyclic = review_declared_chains(
        _document(
            _unsafe_nodes(),
            [
                {"from": "inbox", "to": "records"},
                {"from": "records", "to": "email"},
                {"from": "email", "to": "records"},
            ],
        ),
        generated_at="2026-08-13T00:00:00+00:00",
    )
    assert cyclic["paths"] == [{"identity": ["inbox", "records", "email"]}]

    budgeted = review_declared_chains(
        _document(_unsafe_nodes(), []),
        generated_at="2026-08-13T00:00:00+00:00",
        max_nodes=2,
    )
    assert budgeted["findings"][0]["id"] == "TW-CHAIN-004"


def test_chain_review_never_emits_more_paths_than_the_declared_limit() -> None:
    document = _document(
        [
            {"id": "source", "kind": "source", "trust": "untrusted"},
            {"id": "left", "kind": "tool", "action_class": "read"},
            {"id": "right", "kind": "tool", "action_class": "read"},
            {"id": "sink", "kind": "sink", "action_class": "external"},
        ],
        [
            {"from": "source", "to": "left"},
            {"from": "source", "to": "right"},
            {"from": "left", "to": "sink"},
            {"from": "right", "to": "sink"},
        ],
    )

    review = review_declared_chains(document, max_paths=1)

    assert review["paths"] == [{"identity": ["source", "left", "sink"]}]
    assert any(
        finding["id"] == "TW-CHAIN-004" and finding["properties"]["budget"] == "max_paths"
        for finding in review["findings"]
    )


@pytest.mark.parametrize(
    ("budget", "summary_key"),
    [({"max_states": 1}, "states_explored"), ({"max_edges": 1}, "edges_traversed")],
)
def test_chain_review_never_exceeds_state_or_edge_budget(
    budget: dict[str, int], summary_key: str
) -> None:
    review = review_declared_chains(
        _document(
            _unsafe_nodes(),
            [{"from": "inbox", "to": "records"}, {"from": "records", "to": "email"}],
        ),
        **budget,
    )

    assert review["summary"][summary_key] <= 1
    assert any(
        finding["id"] == "TW-CHAIN-004" and finding["properties"]["budget"] in budget
        for finding in review["findings"]
    )


def test_chain_review_preserves_unsafe_metadata_and_reviewer_facing_report() -> None:
    """Reviewer evidence retains the declared path, classifications, and fixed limit language."""

    review = review_declared_chains(
        _document(
            _unsafe_nodes(),
            [{"from": "inbox", "to": "records"}, {"from": "records", "to": "email"}],
        ),
        generated_at="2026-08-13T00:00:00+00:00",
    )

    first, second = review["findings"]
    assert first["id"] == "TW-CHAIN-001"
    assert first["severity"] == "high"
    assert first["evidence_kind"] == "declared_chain_configuration"
    assert first["message"] == (
        "An explicitly declared untrusted path reaches sensitive data and an external action."
    )
    assert first["subject"] == {"path": ["inbox", "records", "email"]}
    assert first["properties"]["classifications"] == ["confidential"]
    assert second["id"] == "TW-CHAIN-002"
    assert second["severity"] == "high"
    assert second["message"] == (
        "The declared sensitive-data path reaches an external action without a declared "
        "fail-closed approval boundary."
    )
    assert second["subject"] == {"path": ["inbox", "records", "email"]}
    assert second["properties"]["classifications"] == ["confidential"]
    report = render_chain_review(review)
    assert "# Declared Chain Review" in report
    assert "- `inbox -> records -> email`" in report
    assert (
        "**TW-CHAIN-001** (high): An explicitly declared untrusted path reaches sensitive "
        "data and an external action." in report
    )
    assert "a runtime path, exploitability, or deployed control behavior" in report


def test_chain_review_rejects_a_document_at_the_exact_default_node_limit() -> None:
    """The default `max_nodes` bound rejects a 1,001-node declaration deterministically."""

    nodes = [
        {"id": f"node-{index}", "kind": "tool", "action_class": "read"} for index in range(1_001)
    ]
    review = review_declared_chains(_document(nodes, []), generated_at="2026-08-13T00:00:00+00:00")

    finding = review["findings"][0]
    assert finding["id"] == "TW-CHAIN-004"
    assert finding["severity"] == "medium"
    assert finding["message"] == (
        "The declared graph analysis budget was exceeded; the local review is incomplete."
    )
    assert finding["subject"] == {"path": []}
    assert finding["properties"]["budget"] == "max_nodes"
    assert finding["properties"]["max_depth"] == 100
    assert finding["properties"]["max_edges"] == 5000
    assert finding["properties"]["max_paths"] == 1000
    assert finding["properties"]["max_states"] == 5000
    assert finding["location"] == {"path_identity": "analysis_budget"}


@pytest.mark.parametrize(
    ("review", "message"),
    [
        ({"paths": "not-a-list", "findings": []}, "chain_review.paths must be a list"),
        ({"paths": [], "findings": "not-a-list"}, "chain_review.findings must be a list"),
        (
            {"paths": ["not-an-object"], "findings": []},
            "path must be an object",
        ),
        (
            {"paths": [{"identity": "not-a-list"}], "findings": []},
            "path.identity must be a list",
        ),
        (
            {"paths": [], "findings": ["not-an-object"]},
            "finding must be an object",
        ),
    ],
)
def test_chain_renderer_rejects_malformed_public_review_artifacts(
    review: dict[str, object], message: str
) -> None:
    """Chain report rendering fails closed with exact artifact field diagnostics."""

    with pytest.raises(ValidationError) as error:
        render_chain_review(review)
    assert str(error.value) == message


def test_chain_renderer_preserves_clear_review_explanatory_boundary() -> None:
    """A clear supplied declaration renders explicit no-path, no-finding, and scope statements."""

    assert render_chain_review({"paths": [], "findings": []}) == (
        "# Declared Chain Review\n\n"
        "## Declared paths\n\n"
        "- No path from an explicitly declared untrusted source reached an external action.\n\n"
        "## Review findings\n\n"
        "- No reviewer-facing findings were produced from the supplied declarations.\n\n"
        "> This report reviews supplied declared graph metadata only. It does not demonstrate "
        "a runtime path, exploitability, or deployed control behavior.\n"
    )


def test_chain_review_accepts_a_document_at_the_exact_default_node_limit() -> None:
    """The inclusive node budget accepts exactly 1,000 nodes without an incomplete review."""

    nodes = [
        {"id": f"node-{index}", "kind": "tool", "action_class": "read"} for index in range(1_000)
    ]

    review = review_declared_chains(_document(nodes, []), generated_at="2026-08-18T00:00:00+00:00")

    assert review["paths"] == []
    assert review["findings"] == []


@pytest.mark.parametrize(
    ("document", "kwargs", "message"),
    [
        (
            _document(
                [
                    {"id": "source", "kind": "source", "trust": "trusted"},
                    {"id": "sink", "kind": "sink"},
                ],
                [{"from": "source", "to": "sink"}],
            ),
            {},
            "action_class is required",
        ),
        (
            _document(
                [
                    {"id": "source", "kind": "source", "trust": "trusted"},
                    {"id": "approval", "kind": "approval", "fail_closed": "yes"},
                ],
                [{"from": "source", "to": "approval"}],
            ),
            {},
            "fail_closed must be a boolean",
        ),
        (_document([], []), {}, "nodes must not be empty"),
        (_document(_unsafe_nodes(), []), {"max_paths": 0}, "budgets must be positive"),
    ],
)
def test_chain_review_rejects_required_node_and_budget_boundary_values(
    document: dict[str, object], kwargs: dict[str, int], message: str
) -> None:
    """Declared graph validation fails before a public review can omit required semantics."""

    with pytest.raises(ValidationError, match=message):
        review_declared_chains(document, **kwargs)


@pytest.mark.parametrize(
    ("edges", "message"),
    [
        ("not-a-list", "chain_manifest.edges must be a list"),
        (["not-an-object"], "chain_manifest.edges[0] must be an object"),
        (
            [{"from": "source", "to": "sink", "unexpected": True}],
            "chain_manifest.edges[0]: unknown field 'unexpected'",
        ),
        ([{"from": "", "to": "sink"}], "chain_manifest.edges[0].from must be a non-empty string"),
        ([{"from": "source", "to": ""}], "chain_manifest.edges[0].to must be a non-empty string"),
        (
            [{"from": "source", "to": "unknown"}],
            "chain_manifest.edges[0] references an unknown declared node",
        ),
    ],
)
def test_chain_manifest_rejects_malformed_declared_edges(edges: object, message: str) -> None:
    """Every edge must have a bounded object shape and reference declared node identifiers."""

    document = _document(
        [
            {"id": "source", "kind": "source", "trust": "trusted"},
            {"id": "sink", "kind": "sink", "action_class": "read"},
        ],
        [],
    )
    document["edges"] = edges

    with pytest.raises(ValidationError) as error:
        review_declared_chains(document)
    assert str(error.value) == message


def test_chain_manifest_accepts_declared_conditional_source_trust() -> None:
    """Conditional trust is an explicit supported source posture, not an unknown label."""

    review = review_declared_chains(
        _document(
            [
                {
                    "id": "conditional-ingress",
                    "kind": "source",
                    "trust": "conditional",
                    "classification": "internal",
                },
                {"id": "archive", "kind": "sink", "action_class": "write"},
            ],
            [{"from": "conditional-ingress", "to": "archive"}],
        ),
        generated_at="2026-08-18T00:00:00+00:00",
    )

    assert review["paths"] == []
    assert review["findings"] == []


@pytest.mark.parametrize(
    ("nodes", "message"),
    [
        (
            [{"id": "ingress", "kind": "source", "trust": "unknown"}],
            "chain_manifest.nodes[0].trust must be a declared trust label",
        ),
        (
            [{"id": "ingress", "kind": "source", "trust": "trusted", "classification": ""}],
            "chain_manifest.nodes[0].classification must be a non-empty string",
        ),
        (
            [{"id": "email", "kind": "tool", "action_class": "network"}],
            "chain_manifest.nodes[0].action_class must be one of "
            "['external', 'read', 'sensitive', 'write']",
        ),
        (
            [{"id": "redact", "kind": "sanitizer", "covers_classifications": [""]}],
            "chain_manifest.nodes[0].covers_classifications must be a non-empty string",
        ),
    ],
)
def test_chain_manifest_preserves_exact_node_field_diagnostics(
    nodes: list[dict[str, object]], message: str
) -> None:
    """Invalid declared node fields fail closed using stable manifest paths."""

    with pytest.raises(ValidationError) as error:
        review_declared_chains(_document(nodes, []))
    assert str(error.value) == message


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "chain_manifest must be an object"),
        (
            {
                "schema_version": "trustweave.dev/chain-manifest/v1alpha1",
                "name": "chain",
                "nodes": [],
                "edges": [],
                "unexpected": True,
            },
            "chain_manifest: unknown field 'unexpected'",
        ),
        (
            {
                "schema_version": "trustweave.dev/chain-manifest/v1alpha1",
                "name": "",
                "nodes": [],
                "edges": [],
            },
            "chain_manifest.name must be a non-empty string",
        ),
        (
            {
                "schema_version": "trustweave.dev/chain-manifest/v1alpha1",
                "name": "chain",
                "nodes": {},
                "edges": [],
            },
            "chain_manifest.nodes must be a list",
        ),
        (
            {
                "schema_version": "trustweave.dev/chain-manifest/v1alpha1",
                "name": "chain",
                "nodes": ["invalid"],
                "edges": [],
            },
            "chain_manifest.nodes[0] must be an object",
        ),
        (
            {
                "schema_version": "trustweave.dev/chain-manifest/v1alpha1",
                "name": "chain",
                "nodes": [{"id": "", "kind": "source", "trust": "trusted"}],
                "edges": [],
            },
            "chain_manifest.nodes[0].id must be a non-empty string",
        ),
        (
            {
                "schema_version": "trustweave.dev/chain-manifest/v1alpha1",
                "name": "chain",
                "nodes": [{"id": "node", "kind": "unknown"}],
                "edges": [],
            },
            "chain_manifest.nodes[0].kind must be one of "
            "['approval', 'data', 'sanitizer', 'sink', 'source', 'tool']",
        ),
        (
            {
                "schema_version": "trustweave.dev/chain-manifest/v1alpha1",
                "name": "chain",
                "nodes": [],
                "edges": [],
            },
            "chain_manifest.nodes must not be empty",
        ),
    ],
)
def test_chain_manifest_preserves_exact_root_and_node_structure_diagnostics(
    document: object, message: str
) -> None:
    """Malformed manifest structure retains precise root and indexed-node remediation paths."""

    with pytest.raises(ValidationError) as error:
        review_declared_chains(document)
    assert str(error.value) == message


def test_chain_manifest_rejects_duplicate_node_identifiers_with_exact_contract() -> None:
    """Each declared node identifier names one unique fixed topology position."""

    document = _document(
        [
            {"id": "source", "kind": "source", "trust": "trusted"},
            {"id": "source", "kind": "sink", "action_class": "write"},
        ],
        [],
    )

    with pytest.raises(ValidationError) as error:
        review_declared_chains(document)
    assert str(error.value) == "chain_manifest.nodes contains duplicate id: source"


def test_chain_renderer_preserves_exact_single_finding_fields() -> None:
    """A rendered reviewer finding preserves canonical identifier, severity, and message fields."""

    review = {
        "paths": [{"identity": ["inbox", "records", "email"]}],
        "findings": [
            {
                "id": "TW-CHAIN-EXACT",
                "severity": "high",
                "message": "EXPECTED CHAIN REVIEW MESSAGE.",
            }
        ],
    }

    assert render_chain_review(review) == (
        "# Declared Chain Review\n\n"
        "## Declared paths\n\n"
        "- `inbox -> records -> email`\n\n"
        "## Review findings\n\n"
        "- **TW-CHAIN-EXACT** (high): EXPECTED CHAIN REVIEW MESSAGE.\n\n"
        "> This report reviews supplied declared graph metadata only. It does not demonstrate "
        "a runtime path, exploitability, or deployed control behavior.\n"
    )


def test_chain_renderer_preserves_exact_findings_and_empty_state_prose() -> None:
    """Chain output retains exact paths, findings, and safe empty-state prose."""

    rendered = render_chain_review(
        {
            "paths": [{"identity": ["inbox", "external"]}],
            "findings": [
                {
                    "id": "TW-CHAIN-RENDER",
                    "severity": "high",
                    "message": "EXPECTED chain review message.",
                }
            ],
        }
    )
    assert rendered == "\n".join(
        [
            "# Declared Chain Review",
            "",
            "## Declared paths",
            "",
            "- `inbox -> external`",
            "",
            "## Review findings",
            "",
            "- **TW-CHAIN-RENDER** (high): EXPECTED chain review message.",
            "",
            "> This report reviews supplied declared graph metadata only. It does not demonstrate "
            "a runtime path, exploitability, or deployed control behavior.",
            "",
        ]
    )
    assert (
        render_chain_review({"paths": [], "findings": []}).count(
            "No reviewer-facing findings were produced from the supplied declarations."
        )
        == 1
    )


def test_chain_review_processes_sensitive_terminals_after_a_clear_terminal_path() -> None:
    """A clear terminal cannot stop review of later sensitive terminal paths."""

    review = review_declared_chains(
        _document(
            [
                {"id": "a-clear", "kind": "source", "trust": "untrusted"},
                {"id": "b-sensitive", "kind": "source", "trust": "untrusted"},
                {"id": "records", "kind": "data", "classification": "confidential"},
                {"id": "external", "kind": "sink", "action_class": "external"},
            ],
            [
                {"from": "a-clear", "to": "external"},
                {"from": "b-sensitive", "to": "records"},
                {"from": "records", "to": "external"},
            ],
        )
    )

    assert review["paths"] == [
        {"identity": ["a-clear", "external"]},
        {"identity": ["b-sensitive", "records", "external"]},
    ]
    assert [finding["id"] for finding in review["findings"]] == [
        "TW-CHAIN-001",
        "TW-CHAIN-002",
    ]
    assert review["findings"][0]["subject"] == {"path": ["b-sensitive", "records", "external"]}


def test_chain_renderer_uses_the_literal_finding_path_for_malformed_finding_entries() -> None:
    """Renderer diagnostics identify each malformed finding as `finding`, not an internal alias."""

    with pytest.raises(ValidationError) as error:
        render_chain_review({"paths": [], "findings": ["not-a-finding"]})
    assert str(error.value) == "finding must be an object"
