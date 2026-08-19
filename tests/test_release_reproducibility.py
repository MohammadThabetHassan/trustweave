"""Regression coverage for the owner-release clean-checkout reproducibility procedure."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "verify_release_reproducibility.py"
OWNER_CHECKLIST = ROOT / "docs" / "OWNER_RELEASE_CHECKLIST_0.2.0.md"
REPRODUCIBILITY_GUIDE = ROOT / "docs" / "REPRODUCIBILITY.md"
RELEASE_GUIDE = ROOT / "docs" / "RELEASE.md"
TRACKED_RELEASE_INPUTS = (
    ROOT / "examples" / "support-agent.manifest.json",
    ROOT / "policies" / "default-policy.json",
    ROOT / "scenarios" / "default-scenarios.json",
    ROOT / "examples" / "chains" / "safe-sanitized-external.chain.json",
)


def _git(*arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=True,
        capture_output=True,
        encoding="utf-8",
    )
    return completed.stdout


def test_clean_checkout_release_reproducibility_helper_is_self_contained() -> None:
    """The documented release procedure must not depend on a tracked root config file."""

    assert not (ROOT / "trustweave.toml").exists()
    checklist = OWNER_CHECKLIST.read_text(encoding="utf-8")
    reproducibility_guide = REPRODUCIBILITY_GUIDE.read_text(encoding="utf-8")
    release_guide = RELEASE_GUIDE.read_text(encoding="utf-8")
    assert "scripts/verify_release_reproducibility.py" in checklist
    assert "--config trustweave.toml" not in checklist
    assert "scripts/verify_release_reproducibility.py" in reproducibility_guide
    assert "scripts/verify_release_reproducibility.py" in release_guide
    assert all(path.is_file() for path in TRACKED_RELEASE_INPUTS)
    before_status = _git("status", "--porcelain")
    revision = _git("rev-parse", "HEAD").strip()

    completed = subprocess.run(
        [
            sys.executable,
            str(HELPER),
            "--source-revision",
            revision,
            "--allow-dirty",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        encoding="utf-8",
    )

    assert completed.returncode == 0, completed.stderr
    assert "two 10-artifact trees are byte-identical" in completed.stdout
    assert "path-clean" in completed.stdout
    assert "supplied-file attestation verification passed" in completed.stdout
    assert _git("status", "--porcelain") == before_status
