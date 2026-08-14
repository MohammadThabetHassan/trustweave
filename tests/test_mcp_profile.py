from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.cli import main
from trustweave.io import load_document
from trustweave.mcp_profile import parse_mcp_profile, review_mcp_profile
from trustweave.models import ValidationError, parse_manifest
from trustweave.report import render_mcp_profile_review_report

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "support-agent.manifest.json"
CLEAR_PROFILE = ROOT / "examples" / "mcp-profiles" / "clear-support-profile.json"
REVIEW_PROFILE = ROOT / "examples" / "mcp-profiles" / "review-required-support-profile.json"


def _document(path: Path) -> dict[str, object]:
    return json.loads(json.dumps(load_document(path)))


def _review(path: Path) -> dict[str, object]:
    return review_mcp_profile(
        parse_mcp_profile(_document(path)), parse_manifest(_document(MANIFEST))
    )


def test_clear_mcp_profile_maps_to_manifest_without_findings() -> None:
    review = _review(CLEAR_PROFILE)

    assert review["summary"] == {"tools_reviewed": 2, "review_findings": 0, "status": "clear"}
    assert all(mapping["status"] == "clear" for mapping in review["mappings"])


def test_review_required_profile_flags_authorization_and_mapping_drift() -> None:
    review = _review(REVIEW_PROFILE)

    identifiers = {finding["id"] for finding in review["findings"]}
    assert {"TW-MCP-001", "TW-MCP-002", "TW-MCP-003"}.issubset(identifiers)
    assert review["summary"]["status"] == "review_required"
    assert "mcp.synthetic.invalid" in render_mcp_profile_review_report(review)


def test_http_profile_rejects_query_credentials_and_fragments() -> None:
    profile = _document(CLEAR_PROFILE)
    profile["resource_uri"] = (
        "https://user:secret@mcp.synthetic.invalid/support?token=secret#fragment"
    )

    with pytest.raises(ValidationError, match="must not contain credentials"):
        parse_mcp_profile(profile)


def test_cli_mcp_profile_check_writes_artifacts_and_can_fail_review_gate(tmp_path: Path) -> None:
    clear_dir = tmp_path / "clear"
    assert (
        main(
            [
                "mcp-profile-check",
                "--manifest",
                str(MANIFEST),
                "--profile",
                str(CLEAR_PROFILE),
                "--output-dir",
                str(clear_dir),
                "--exit-on-review",
            ]
        )
        == 0
    )
    assert (clear_dir / "mcp-profile-review.json").is_file()
    assert (clear_dir / "mcp-profile-review.md").is_file()

    review_dir = tmp_path / "review"
    assert (
        main(
            [
                "mcp-profile-check",
                "--manifest",
                str(MANIFEST),
                "--profile",
                str(REVIEW_PROFILE),
                "--output-dir",
                str(review_dir),
                "--exit-on-review",
            ]
        )
        == 1
    )
    assert (review_dir / "mcp-profile-review.json").is_file()
    assert (review_dir / "mcp-profile-review.md").is_file()


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda profile: profile.update({"schema_version": "unsupported"}), "schema_version"),
        (lambda profile: profile.update({"transport": "websocket"}), "transport"),
        (lambda profile: profile.update({"authorization_expected": "false"}), "boolean"),
        (lambda profile: profile.update({"resource_uri": "relative/path"}), "absolute HTTP"),
        (lambda profile: profile.update({"tools": []}), "at least one tool"),
        (
            lambda profile: profile["tools"].append(dict(profile["tools"][0])),
            "mcp_profile.tools.name contains duplicate",
        ),
    ],
)
def test_mcp_profile_parser_rejects_invalid_static_contracts(mutate: object, message: str) -> None:
    profile = _document(CLEAR_PROFILE)
    assert callable(mutate)
    mutate(profile)

    with pytest.raises(ValidationError, match=message):
        parse_mcp_profile(profile)


def test_stdio_profile_retains_an_explicit_local_identifier_without_http_validation() -> None:
    profile = _document(CLEAR_PROFILE)
    profile["transport"] = "stdio"
    profile["resource_uri"] = "local-reviewable-stdio-identifier"

    parsed = parse_mcp_profile(profile)

    assert parsed.transport == "stdio"
    assert parsed.resource_uri == "local-reviewable-stdio-identifier"
