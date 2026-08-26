from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = ROOT / "demo" / "declaration-consistency"
CASE_IDS = tuple(f"TW-COMP-{number:03d}" for number in range(1, 15))


def test_every_benchmark_case_has_a_checked_in_terminal_gif_and_cast() -> None:
    readme = (DEMO_DIR / "README.md").read_text(encoding="utf-8")

    for case_id in CASE_IDS:
        cast_path = DEMO_DIR / "cases" / f"{case_id}.cast"
        gif_path = DEMO_DIR / "cases" / f"{case_id}.gif"
        assert cast_path.is_file()
        assert gif_path.read_bytes().startswith((b"GIF87a", b"GIF89a"))
        assert f"cases/{case_id}.gif" in readme
        assert f"cases/{case_id}.cast" in readme

        cast_lines = cast_path.read_text(encoding="utf-8").splitlines()
        header = json.loads(cast_lines[0])
        assert header["version"] == 2
        assert case_id in header["title"]
        assert any(f"Case: {case_id}" in line for line in cast_lines[1:])


def test_mutation_sandbox_copies_checked_in_demo_assets() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert '  "demo",' in pyproject


def test_terminal_demo_runner_preserves_the_local_only_boundary() -> None:
    runner = (DEMO_DIR / "run-case.sh").read_text(encoding="utf-8")
    readme = (DEMO_DIR / "README.md").read_text(encoding="utf-8")

    assert "--case" in runner
    assert "verify_declaration_completeness_provenance.py" in runner
    assert "no framework execution" in runner
    assert "synthetic local fixtures" in readme
    assert "not evidence of a live framework run" in readme
