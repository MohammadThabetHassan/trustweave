from __future__ import annotations

import json
from pathlib import Path

from trustweave import api

ROOT = Path(__file__).resolve().parents[1]


def test_public_api_exports_only_documented_data_only_services() -> None:
    assert api.__all__ == sorted(api.__all__)
    for name in api.__all__:
        assert hasattr(api, name)

    manifest = api.parse_manifest(
        json.loads((ROOT / "examples" / "support-agent.manifest.json").read_text(encoding="utf-8"))
    )
    policy = api.parse_policy(
        json.loads((ROOT / "policies" / "default-policy.json").read_text(encoding="utf-8"))
    )
    bundle = api.build_bundle(manifest, policy, generated_at="2026-08-13T00:00:00+00:00")
    assert bundle["schema_version"] == "trustweave.dev/bundle/v1alpha1"
    assert bundle["summary"]["deny"] == 2
