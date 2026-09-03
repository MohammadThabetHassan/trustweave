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


def test_the_publish_refusal_counts_and_names_the_entries_it_found(tmp_path: Path) -> None:
    """The message must let a reviewer see what would have been destroyed."""

    output = tmp_path / "artifacts"
    output.mkdir()
    for index in range(8):
        (output / f"file{index}.txt").write_text("work", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()

    with pytest.raises(InputOutputError) as raised:
        _publish_directory(staging, output)

    message = str(raised.value)
    assert "8 entries" in message
    assert "file0.txt" in message
    # Only the first five are listed; the rest are counted.
    assert "and 3 more" in message


def test_a_small_number_of_entries_is_listed_without_a_more_suffix(tmp_path: Path) -> None:
    output = tmp_path / "artifacts"
    output.mkdir()
    (output / "notes.txt").write_text("work", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()

    with pytest.raises(InputOutputError) as raised:
        _publish_directory(staging, output)

    assert "more)" not in str(raised.value)


def test_hidden_entries_do_not_block_publication(tmp_path: Path) -> None:
    """Editor and tooling dotfiles are not a reason to refuse an artifact directory."""

    output = tmp_path / "artifacts"
    output.mkdir()
    (output / ".gitkeep").write_text("", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "report.md").write_text("fresh", encoding="utf-8")

    _publish_directory(staging, output)

    assert (output / "report.md").read_text(encoding="utf-8") == "fresh"


def test_publication_into_a_missing_directory_is_allowed(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "report.md").write_text("fresh", encoding="utf-8")

    _publish_directory(staging, tmp_path / "absent")

    assert (tmp_path / "absent" / "report.md").exists()


def test_the_artifact_allow_list_covers_both_shared_and_ci_owned_names() -> None:
    from trustweave.commands.ci import _known_artifact_names

    known = _known_artifact_names()

    assert "agent-security-bundle.json" in known
    assert "ci-summary.json" in known
    assert "code-discovery.json" in known


def test_exactly_five_unrelated_entries_are_listed_without_a_more_suffix(
    tmp_path: Path,
) -> None:
    """The boundary is > 5, not >= 5: five entries all fit in the list."""

    output = tmp_path / "artifacts"
    output.mkdir()
    for index in range(5):
        (output / f"file{index}.txt").write_text("work", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()

    with pytest.raises(InputOutputError) as raised:
        _publish_directory(staging, output)

    message = str(raised.value)
    assert "5 entries" in message
    assert "more" not in message


def test_the_publish_refusal_message_is_exact(tmp_path: Path) -> None:
    """A reviewer acts on this sentence, so its wording and separators are a contract."""

    output = tmp_path / "artifacts"
    output.mkdir()
    (output / "beta.txt").write_text("work", encoding="utf-8")
    (output / "alpha.txt").write_text("work", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()

    with pytest.raises(InputOutputError) as raised:
        _publish_directory(staging, output)

    assert str(raised.value) == (
        f"Refusing to publish CI artifacts into {output}: it holds 2 entries TrustWeave "
        "did not write (alpha.txt, beta.txt). Point output_dir at a dedicated directory, "
        "or empty this one first."
    )


def test_the_artifact_allow_list_holds_only_filenames(tmp_path: Path) -> None:
    """Every entry is a *_FILE constant; schema versions and other strings stay out."""

    from trustweave.commands.ci import CI_SUMMARY_SCHEMA_VERSION, _known_artifact_names

    known = _known_artifact_names()

    assert CI_SUMMARY_SCHEMA_VERSION not in known
    assert all("/" not in name for name in known)
    assert all(name.count(".") == 1 for name in known)


def test_at_most_five_entries_are_listed_and_the_rest_are_counted(tmp_path: Path) -> None:
    """Six entries: five named, one counted. Pins both the slice and the threshold."""

    output = tmp_path / "artifacts"
    output.mkdir()
    for name in ("a.txt", "b.txt", "c.txt", "d.txt", "e.txt", "f.txt"):
        (output / name).write_text("work", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()

    with pytest.raises(InputOutputError) as raised:
        _publish_directory(staging, output)

    assert str(raised.value) == (
        f"Refusing to publish CI artifacts into {output}: it holds 6 entries TrustWeave "
        "did not write (a.txt, b.txt, c.txt, d.txt, e.txt and 1 more). Point output_dir "
        "at a dedicated directory, or empty this one first."
    )
