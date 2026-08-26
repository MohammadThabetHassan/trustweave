#!/usr/bin/env python3
"""Render paced terminal GIFs from actual declaration-consistency case walkthroughs."""

from __future__ import annotations

import json
import os
import subprocess
import textwrap
from pathlib import Path
from typing import Final

from PIL import Image, ImageDraw, ImageFont

ROOT: Final[Path] = Path(__file__).resolve().parents[1]
DEMO_DIR: Final[Path] = ROOT / "demo" / "declaration-consistency"
CASE_DIR: Final[Path] = DEMO_DIR / "cases"
FONT_PATH: Final[Path] = DEMO_DIR / "assets" / "DejaVuSansMono.ttf"
RUNNER: Final[Path] = DEMO_DIR / "run-case.sh"
BENCHMARK: Final[Path] = (
    ROOT / "examples" / "evaluation-corpus" / "declaration-completeness" / "benchmark.json"
)
CASE_IDS: Final[tuple[str, ...]] = tuple(f"TW-COMP-{number:03d}" for number in range(1, 15))
WIDTH: Final[int] = 1200
HEIGHT: Final[int] = 720
PADDING_X: Final[int] = 48
PADDING_Y: Final[int] = 64
LINE_HEIGHT: Final[int] = 24
MAX_LINES: Final[int] = 24
TERMINAL_COLUMNS: Final[int] = 104
INTRO_DURATION_MS: Final[int] = 6_500
COMMAND_DURATION_MS: Final[int] = 2_400
OUTRO_DURATION_MS: Final[int] = 6_000
CAST_LINE_DELAY_SECONDS: Final[float] = 0.95
FIXED_TIMESTAMP: Final[int] = 1_767_000_000


class _DemoFrame(tuple[list[str], int]):
    """A terminal screen and the time it remains visible in the GIF."""


def _font(size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(FONT_PATH, size=size)


def _capture_case(case_id: str) -> list[str]:
    result = subprocess.run(
        [str(RUNNER), case_id],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    return result.stdout.splitlines()


def _case(case_id: str) -> dict[str, object]:
    fixture = json.loads(BENCHMARK.read_text(encoding="utf-8"))
    for item in fixture["cases"]:
        if item["id"] == case_id:
            return item
    raise ValueError(f"Unknown benchmark case: {case_id}")


def _expected_result(case: dict[str, object]) -> str:
    expected = case["expected"]
    if not isinstance(expected, dict):
        raise ValueError("Benchmark fixture has an invalid expected result")

    status = expected["status"]
    missing = expected["unresolved_missing_from_manifest"]
    manifest_only = expected["unresolved_manifest_only_tools"]
    reconciliations = expected["declared_reconciliations"]
    if not all(isinstance(value, list) for value in (missing, manifest_only, reconciliations)):
        raise ValueError("Benchmark fixture has invalid expected label collections")

    unresolved = len(missing) + len(manifest_only)
    if status == "complete":
        return "exact agreement — no raw label differences are expected."
    if status == "declared_reconciliation":
        return (
            "declared reconciliation — raw differences stay visible, with all pairs explicitly "
            "mapped by the fixture maintainer."
        )
    return (
        f"mismatch — {unresolved} unresolved supplied label difference(s) remain after "
        f"{len(reconciliations)} explicit local mapping(s)."
    )


def _terminal_header(case_id: str) -> list[str]:
    return [
        "TrustWeave declaration-consistency walkthrough",
        f"{case_id} — supplied local static labels only",
        "",
    ]


def _case_brief(case_id: str) -> list[str]:
    case = _case(case_id)
    framework = str(case["framework"]).replace("-", " ")
    return _terminal_header(case_id) + [
        f"Scenario: {case['title']}",
        f"Fixture form: supplied {framework} descriptor ↔ supplied TrustWeave manifest.",
        (
            "Review question: do the supplied static tool labels agree, and which differences "
            "need review?"
        ),
        f"Expected bounded result: {_expected_result(case)}",
        f"Why this control matters: {case['rationale']}",
        (
            "Scope: synthetic local control; no framework execution, source inspection, input "
            "authentication, or runtime claim."
        ),
        "",
        "Next: run the actual local contract, provenance, and reviewer-summary commands.",
    ]


def _case_outro(case_id: str) -> list[str]:
    case = _case(case_id)
    return _terminal_header(case_id) + [
        (
            "Walkthrough complete: the actual local commands reproduced the fixture's expected "
            "bounded result."
        ),
        (
            "Use: inspect raw supplied label differences and any explicit maintainer mappings in "
            "the generated summary."
        ),
        f"Limit: {case['non_claim']}",
        "",
        (
            "This is a reproducible synthetic control, not deployment, runtime, or "
            "independent-validation evidence."
        ),
    ]


def _wrap_lines(lines: list[str]) -> list[str]:
    wrapped: list[str] = []
    for line in lines:
        if not line:
            wrapped.append("")
            continue
        wrapped.extend(
            textwrap.wrap(
                line,
                width=TERMINAL_COLUMNS,
                break_long_words=False,
                break_on_hyphens=False,
                subsequent_indent="  ",
            )
            or [""]
        )
    return wrapped


def _window(lines: list[str]) -> list[str]:
    wrapped = _wrap_lines(lines)
    if len(wrapped) <= MAX_LINES:
        return wrapped
    return wrapped[:MAX_LINES]


def _frames(lines: list[str], case_id: str) -> list[_DemoFrame]:
    selected = [line for line in lines if line.strip()]
    header = _terminal_header(case_id)
    frames: list[_DemoFrame] = [_DemoFrame((_window(_case_brief(case_id)), INTRO_DURATION_MS))]

    for index in range(0, len(selected), 4):
        window = selected[index : index + 4]
        visible = selected[: index + len(window)]
        frame_lines = header + visible
        if len(_wrap_lines(frame_lines)) > MAX_LINES:
            frame_lines = header + selected[max(0, index - 12) : index + len(window)]
        frames.append(_DemoFrame((_window(frame_lines), COMMAND_DURATION_MS)))

    frames.append(_DemoFrame((_window(_case_outro(case_id)), OUTRO_DURATION_MS)))
    return frames


def _render_frame(lines: list[str]) -> Image.Image:
    image = Image.new("RGB", (WIDTH, HEIGHT), "#15161d")
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle(
        (16, 16, WIDTH - 16, HEIGHT - 16), radius=24, fill="#101116", outline="#303541", width=2
    )
    draw.ellipse((44, 40, 60, 56), fill="#ff5f57")
    draw.ellipse((70, 40, 86, 56), fill="#ffbd2e")
    draw.ellipse((96, 40, 112, 56), fill="#28c840")
    draw.text(
        (150, 35), "trustweave — declaration-consistency review", fill="#abb2bf", font=_font(18)
    )
    y = PADDING_Y + 36
    for index, line in enumerate(lines):
        color = "#d7dae0"
        if index == 0:
            color = "#79d6c8"
        elif index == 1:
            color = "#9fb3c8"
        elif line.startswith("$"):
            color = "#f3c969"
        elif "passed" in line.lower() or "complete" in line.lower():
            color = "#83d48f"
        elif "mismatch" in line.lower() or "unresolved" in line.lower():
            color = "#f0b36b"
        draw.text((PADDING_X, y), line, fill=color, font=_font(18))
        y += LINE_HEIGHT
    return image


def _write_cast(case_id: str, lines: list[str], destination: Path) -> None:
    header = {
        "version": 2,
        "width": 120,
        "height": 32,
        "timestamp": FIXED_TIMESTAMP,
        "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
        "title": f"TrustWeave declaration-consistency — {case_id}",
    }
    events: list[str] = [json.dumps(header, sort_keys=True)]
    timestamp = 0.0
    for line in lines:
        events.append(json.dumps([round(timestamp, 2), "o", f"{line}\r\n"]))
        timestamp += CAST_LINE_DELAY_SECONDS
    destination.write_text("\n".join(events) + "\n", encoding="utf-8")


def render_case(case_id: str) -> None:
    output_lines = _capture_case(case_id)
    walkthrough_lines = _case_brief(case_id) + [""] + output_lines + [""] + _case_outro(case_id)
    CASE_DIR.mkdir(parents=True, exist_ok=True)
    _write_cast(case_id, walkthrough_lines, CASE_DIR / f"{case_id}.cast")
    frames = _frames(output_lines, case_id)
    rendered = [_render_frame(lines) for lines, _ in frames]
    durations = [duration for _, duration in frames]
    rendered[0].save(
        CASE_DIR / f"{case_id}.gif",
        save_all=True,
        append_images=rendered[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )


def main() -> None:
    for case_id in CASE_IDS:
        render_case(case_id)
        print(f"Rendered paced terminal demo: {case_id}")


if __name__ == "__main__":
    main()
