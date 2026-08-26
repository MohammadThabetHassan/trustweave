#!/usr/bin/env python3
"""Render checked-in terminal GIFs from actual declaration-consistency case walkthroughs."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Final

from PIL import Image, ImageDraw, ImageFont

ROOT: Final[Path] = Path(__file__).resolve().parents[1]
DEMO_DIR: Final[Path] = ROOT / "demo" / "declaration-consistency"
CASE_DIR: Final[Path] = DEMO_DIR / "cases"
RUNNER: Final[Path] = DEMO_DIR / "run-case.sh"
CASE_IDS: Final[tuple[str, ...]] = tuple(f"TW-COMP-{number:03d}" for number in range(1, 15))
WIDTH: Final[int] = 1200
HEIGHT: Final[int] = 720
PADDING_X: Final[int] = 48
PADDING_Y: Final[int] = 64
LINE_HEIGHT: Final[int] = 24
FRAME_DURATION_MS: Final[int] = 700
MAX_LINES: Final[int] = 24
FIXED_TIMESTAMP: Final[int] = 1_767_000_000


def _font(size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", size=size)


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


def _frames(lines: list[str], case_id: str) -> list[list[str]]:
    selected = [line for line in lines if line.strip()]
    headline = [
        "TrustWeave declaration-consistency demo",
        f"{case_id} — supplied local static labels only",
        "No framework execution · no runtime claim",
        "",
    ]
    frames: list[list[str]] = []
    for index in range(0, len(selected), 7):
        window = selected[index : index + 7]
        frame_lines = headline + selected[: min(index + 7, len(selected))]
        if len(frame_lines) > MAX_LINES:
            frame_lines = headline + selected[max(0, index - 13) : index + len(window)]
        frames.append(frame_lines[:MAX_LINES])
    return frames or [headline]


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
        elif index in {1, 2}:
            color = "#9fb3c8"
        elif line.startswith("$"):
            color = "#f3c969"
        elif "passed" in line.lower() or "complete" in line.lower():
            color = "#83d48f"
        elif "mismatch" in line.lower() or "unresolved" in line.lower():
            color = "#f0b36b"
        draw.text((PADDING_X, y), line[:112], fill=color, font=_font(18))
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
        timestamp += 0.12
    destination.write_text("\n".join(events) + "\n", encoding="utf-8")


def render_case(case_id: str) -> None:
    lines = _capture_case(case_id)
    CASE_DIR.mkdir(parents=True, exist_ok=True)
    _write_cast(case_id, lines, CASE_DIR / f"{case_id}.cast")
    rendered = [_render_frame(frame) for frame in _frames(lines, case_id)]
    rendered[0].save(
        CASE_DIR / f"{case_id}.gif",
        save_all=True,
        append_images=rendered[1:],
        duration=FRAME_DURATION_MS,
        loop=0,
        optimize=True,
    )


def main() -> None:
    for case_id in CASE_IDS:
        render_case(case_id)
        print(f"Rendered terminal demo: {case_id}")


if __name__ == "__main__":
    main()
