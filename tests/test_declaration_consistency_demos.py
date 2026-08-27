from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = ROOT / "demo" / "declaration-consistency"
BENCHMARK_PATH = (
    ROOT / "examples" / "evaluation-corpus" / "declaration-completeness" / "benchmark.json"
)
MAX_GIF_BYTES = 600 * 1024
MAX_CAST_BYTES = 12 * 1024
MAX_GALLERY_GIF_BYTES = 8 * 1024 * 1024
MAX_FONT_BYTES = 400 * 1024


def _benchmark_case_ids() -> tuple[str, ...]:
    benchmark = json.loads(BENCHMARK_PATH.read_text(encoding="utf-8"))
    return tuple(case["id"] for case in benchmark["cases"])


def test_every_benchmark_case_has_a_checked_in_terminal_gif_and_cast() -> None:
    case_ids = _benchmark_case_ids()
    readme = (DEMO_DIR / "README.md").read_text(encoding="utf-8")
    cases_dir = DEMO_DIR / "cases"

    assert {path.stem for path in cases_dir.glob("*.cast")} == set(case_ids)
    assert {path.stem for path in cases_dir.glob("*.gif")} == set(case_ids)

    for case_id in case_ids:
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


def test_demo_readme_keeps_a_representative_first_reading_path() -> None:
    """Keep the initial gallery orientation concise while retaining every reproducible case."""

    readme = (DEMO_DIR / "README.md").read_text(encoding="utf-8")

    assert "## Start with these four controls" in readme
    assert "## Full gallery" in readme
    for case_id in ("TW-COMP-002", "TW-COMP-004", "TW-COMP-011", "TW-COMP-014"):
        assert f"[`{case_id}`](cases/{case_id}.gif)" in readme
        assert f"![Terminal walkthrough for {case_id}](cases/{case_id}.gif)" in readme


def test_demo_assets_stay_within_the_reviewed_repository_budget() -> None:
    """Keep optional visual review aids proportionate to the synthetic fixture suite."""

    gif_paths = sorted((DEMO_DIR / "cases").glob("*.gif"))
    cast_paths = sorted((DEMO_DIR / "cases").glob("*.cast"))

    assert gif_paths
    assert len(gif_paths) == len(cast_paths)
    assert all(path.stat().st_size <= MAX_GIF_BYTES for path in gif_paths)
    assert all(path.stat().st_size <= MAX_CAST_BYTES for path in cast_paths)
    assert sum(path.stat().st_size for path in gif_paths) <= MAX_GALLERY_GIF_BYTES
    assert (DEMO_DIR / "assets" / "DejaVuSansMono.ttf").stat().st_size <= MAX_FONT_BYTES


@pytest.mark.skipif(
    os.name == "nt",
    reason=(
        "The checked-in walkthrough runner is a Bash script; transcript execution is verified "
        "on POSIX."
    ),
)
def test_every_cast_preserves_its_captured_runner_output_exactly() -> None:
    start_marker = "== Captured terminal output begins (emitted by run-case.sh) =="
    end_marker = "== Captured terminal output ends (no lines altered by the renderer) =="

    try:
        for case_id in _benchmark_case_ids():
            result = subprocess.run(
                [
                    "bash",
                    (DEMO_DIR / "run-case.sh").relative_to(ROOT).as_posix(),
                    case_id,
                ],
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
    assert "optional maintainer tools" in readme
    assert "not imported by the `trustweave` package" in readme
    assert "each GIF must be at most **600 KiB**" in readme
