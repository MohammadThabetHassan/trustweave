"""Regression contracts for current bundle-diff documentation claims."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_current_bundle_diff_guidance_consistently_names_v1alpha3() -> None:
    """Maintained product guidance must distinguish current v1alpha3 output from readers."""

    expected_markers = {
        "docs/ARCHITECTURE.md": "The current v1alpha3 bundle-diff artifact",
        "docs/MATURITY_PLAN.md": "v1alpha3 policy-aware bundle diff",
        "docs/ROADMAP.md": "current generated bundle diffs use v1alpha3",
    }
    for relative_path, marker in expected_markers.items():
        text = (ROOT / relative_path).read_text(encoding="utf-8")
        assert marker in text
        assert "current v1alpha2 bundle-diff" not in text
