"""Regression contracts for maintainer-owned quality and governance guidance."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_maintainer_handoff_preserves_review_and_owner_control_boundaries() -> None:
    """The operating guide must retain its exact-SHA and non-claim review controls."""

    handoff = (ROOT / "docs" / "MAINTAINER_HANDOFF.md").read_text(encoding="utf-8")
    for marker in (
        "## Merge decision record",
        "exact head SHA",
        "## Owner-controlled GitHub settings",
        "cannot manufacture an approval",
        "## Failed-check response",
        "## Recurring assurance review",
        "## Release boundary",
        "does not itself authorize a merge, tag, package publication, signature, GitHub Release",
    ):
        assert marker in handoff


def test_contributor_workflow_uses_exact_file_attestation_verification() -> None:
    """Contributors must be guided to verify supplied local evidence bytes, not statements alone."""

    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "trustweave verify \\" in contributing
    assert "--attestation artifacts/attestation.json" in contributing
    assert "--bundle artifacts/agent-security-bundle.json" in contributing
    assert "--test-results artifacts/security-test-results.json" in contributing


def test_review_routing_and_template_cover_release_sensitive_changes() -> None:
    """Review routing and PR fields must surface the paths needing maintainer attention."""

    codeowners = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    for path in ("/src/", "/schemas/", "/policies/", "/scripts/", "/docs/", "/.github/"):
        assert f"{path} @MohammadThabetHassan" in codeowners

    template = (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
    for marker in (
        "## Exact review target",
        "Reviewed head SHA",
        "## Release-sensitive or governance impact",
        "## Maintainer review completion",
        "do not create approval automatically",
    ):
        assert marker in template


def test_maintainer_operating_guidance_is_discoverable_from_quality_and_site_navigation() -> None:
    """The handoff must be reachable from both maintainer quality docs and the public site."""

    quality = (ROOT / "docs" / "QUALITY.md").read_text(encoding="utf-8")
    governance = (ROOT / "GOVERNANCE.md").read_text(encoding="utf-8")
    site_page = (ROOT / "docs" / "site" / "MAINTAINERS.md").read_text(encoding="utf-8")
    mkdocs = (ROOT / "mkdocs.yml").read_text(encoding="utf-8")

    assert "[Maintainer Handoff](MAINTAINER_HANDOFF.md)" in quality
    assert "[Maintainer Handoff](docs/MAINTAINER_HANDOFF.md)" in governance
    assert "The full versioned operating record is maintained" in site_page
    assert "cannot manufacture an approval" in site_page
    assert "[release process](RELEASE.md)" in site_page
    assert "Maintainer review and release boundary: MAINTAINERS.md" in mkdocs


def test_product_contract_requires_maintainer_evidence_and_extension_admission() -> None:
    """Future scope expansion must retain explicit evidence and approval conditions."""

    product_contract = (ROOT / "docs" / "PRODUCT_CONTRACT.md").read_text(encoding="utf-8")
    assert "Maintainers record the exact reviewed SHA" in product_contract
    assert "## Extension admission rule" in product_contract
    assert "separate threat model and owner-approved operating procedure" in product_contract
