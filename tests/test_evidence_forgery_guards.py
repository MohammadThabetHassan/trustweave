"""Guards for the two ways a passing verification could previously mean nothing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.cli import main
from trustweave.commands.ci import _publish_directory
from trustweave.models import InputOutputError

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "support-agent.manifest.json"
POLICY = ROOT / "policies" / "default-policy.json"
SCENARIOS = ROOT / "scenarios" / "default-scenarios.json"


def _evidence(output: Path) -> None:
    assert (
        main(
            [
                "scan",
                "--manifest",
                str(MANIFEST),
                "--policy",
                str(POLICY),
                "--output-dir",
                str(output),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "test",
                "--policy",
                str(POLICY),
                "--scenarios",
                str(SCENARIOS),
                "--output-dir",
                str(output),
            ]
        )
        == 0
    )


def test_attest_refuses_a_bundle_whose_findings_contradict_its_declarations(
    tmp_path: Path,
) -> None:
    """Hashing binds bytes to bytes; it cannot see a finding edited from deny to allow."""

    _evidence(tmp_path)
    bundle_path = tmp_path / "agent-security-bundle.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    assert any(finding.get("decision") == "deny" for finding in bundle["findings"])
    for finding in bundle["findings"]:
        finding["decision"] = "allow"
        finding["severity"] = "info"
    bundle_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")

    # The CLI turns a validation failure into exit status 2 rather than raising.
    assert main(["attest", "--source-revision", "forged", "--output-dir", str(tmp_path)]) == 2
    assert not (tmp_path / "attestation.json").exists()


def test_attest_still_accepts_an_unmodified_bundle(tmp_path: Path) -> None:
    _evidence(tmp_path)

    assert main(["attest", "--source-revision", "clean", "--output-dir", str(tmp_path)]) == 0


def test_ci_refuses_to_publish_over_a_directory_it_did_not_write(tmp_path: Path) -> None:
    """A one-word output_dir typo previously deleted the named directory's contents."""

    output = tmp_path / "mysrc"
    output.mkdir()
    (output / "a.txt").write_text("important work", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()

    with pytest.raises(InputOutputError, match="did not write"):
        _publish_directory(staging, output)

    assert (output / "a.txt").read_text(encoding="utf-8") == "important work"


def test_ci_still_publishes_over_its_own_previous_artifacts(tmp_path: Path) -> None:
    output = tmp_path / "artifacts"
    output.mkdir()
    (output / "agent-security-bundle.json").write_text("{}", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "report.md").write_text("fresh", encoding="utf-8")

    _publish_directory(staging, output)

    assert (output / "report.md").read_text(encoding="utf-8") == "fresh"
