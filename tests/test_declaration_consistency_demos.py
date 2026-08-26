from __future__ import annotations

import json
import shutil
import subprocess
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
        events = [json.loads(line) for line in cast_lines[1:]]
        output = "".join(event[2] for event in events)
        assert f"Case: {case_id}" in output
        assert "Scenario:" in output
        assert "Review question:" in output
        assert "Expected bounded result:" in output
        assert "Walkthrough complete:" in output
        assert events[1][0] - events[0][0] >= 0.9


def test_every_cast_preserves_its_captured_runner_output_exactly() -> None:
    start_marker = "== Captured terminal output begins (emitted by run-case.sh) =="
    end_marker = "== Captured terminal output ends (no lines altered by the renderer) =="

    try:
        for case_id in CASE_IDS:
            result = subprocess.run(
                ["bash", str(DEMO_DIR / "run-case.sh"), case_id],
                cwd=ROOT,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            cast_lines = (
                (DEMO_DIR / "cases" / f"{case_id}.cast")
                .read_text(encoding="utf-8")
                .splitlines()[1:]
            )
            rendered_lines = [json.loads(line)[2].removesuffix("\r\n") for line in cast_lines]
            start = rendered_lines.index(start_marker)
            end = rendered_lines.index(end_marker)

            assert rendered_lines[start + 1 : end] == result.stdout.splitlines()
    finally:
        shutil.rmtree(DEMO_DIR / "artifacts", ignore_errors=True)


def test_mutation_sandbox_copies_checked_in_demo_assets() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert '  "demo",' in pyproject


def test_terminal_demo_runner_preserves_the_local_only_boundary() -> None:
    runner = (DEMO_DIR / "run-case.sh").read_text(encoding="utf-8")
    renderer = (ROOT / "scripts" / "render_declaration_consistency_demos.py").read_text(
        encoding="utf-8"
    )
    readme = (DEMO_DIR / "README.md").read_text(encoding="utf-8")

    assert (DEMO_DIR / "assets" / "DejaVuSansMono.ttf").is_file()
    assert (DEMO_DIR / "assets" / "DEJAVU_FONT_LICENSE.txt").is_file()
    assert "FONT_PATH" in renderer
    assert "Captured terminal output begins" in renderer
    assert "no lines altered by the renderer" in renderer
    assert "/usr/share/fonts" not in renderer
    assert "--case" in runner
    assert "verify_declaration_completeness_provenance.py" in runner
    assert "no framework execution" in runner
    assert "synthetic local fixtures" in readme
    assert "not evidence of a live framework run" in readme
