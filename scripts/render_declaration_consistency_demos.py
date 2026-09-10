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
# Narrowed from 1200. Revealing output three lines at a time rather than four is worth
# more than the extra columns, and the two changes together have to fit the 600 KiB budget
# each case is held to.
# A dozen colours is all a terminal render uses, so the palette is quantised on save;
# that is what pays for the wider canvas and the smoother reveal.
PALETTE_COLORS: Final[int] = 64
WIDTH: Final[int] = 1200
# The canvas used to be a fixed 720px while most frames filled about 430, so every GIF
# carried a third of a screen of empty terminal. Height is now derived from the tallest
# frame in the case, with MIN_HEIGHT keeping short cases from looking cramped.
MIN_HEIGHT: Final[int] = 360
# Clear band at the foot of the terminal for the captured-output label.
CAPTION_STRIP: Final[int] = 84
PADDING_X: Final[int] = 48
PADDING_Y: Final[int] = 64
LINE_HEIGHT: Final[int] = 24
MAX_LINES: Final[int] = 24
TERMINAL_COLUMNS: Final[int] = 104
INTRO_DURATION_MS: Final[int] = 5_000
COMMAND_DURATION_MS: Final[int] = 1_500
OUTRO_DURATION_MS: Final[int] = 4_500
CAST_LINE_DELAY_SECONDS: Final[float] = 0.95
FIXED_TIMESTAMP: Final[int] = 1_767_000_000
# The distinction between output `run-case.sh` actually emitted and lines the renderer
# added is deliberate and documented, so it stays. It used to be drawn as two full-width
# banner lines inside the terminal body, which made the demo appear to narrate itself. The
# same distinction is now carried visually: captured lines get a gutter rule and one dim
# caption, so a viewer can still see exactly which lines are verbatim.
CAPTURED_CAPTION: Final[str] = "verbatim output of run-case.sh"
# Retained for the cast, which is a text format and has no gutter to draw.
CAPTURED_OUTPUT_START: Final[str] = "== Captured terminal output begins (emitted by run-case.sh) =="
CAPTURED_OUTPUT_END: Final[str] = (
    "== Captured terminal output ends (no lines altered by the renderer) =="
)


class _DemoFrame(tuple[list[str], int]):
    """A terminal screen and the time it remains visible in the GIF."""


def _font(size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(FONT_PATH, size=size)


def _capture_case(case_id: str) -> list[str]:
    result = subprocess.run(
        ["bash", str(RUNNER), case_id],
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
    """The briefing shown before the commands run.

    This was seven labelled fields -- scenario, fixture form, review question, expected
    result, why it matters, scope, next -- which fills a screen and reads as a form rather
    than as something a person wrote. A reviewer needs three things before watching a run:
    what is being compared, what answer would be correct, and what the fixture does not
    claim. The rest is in the benchmark record and in this directory's README.
    """

    case = _case(case_id)
    framework = str(case["framework"]).replace("-", " ")
    return _terminal_header(case_id) + [
        f"{case['title']}.",
        f"Comparing a supplied {framework} descriptor against a supplied TrustWeave manifest.",
        f"Correct outcome: {_expected_result(case)}",
        "",
        "Synthetic fixture: static labels only, no framework execution and no runtime claim.",
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
    """One frame per pair of captured lines, so output arrives like a session.

    Four lines at a time made the animation read as a slideshow of full screens. Two
    advances at roughly the speed someone skims a terminal, and quantising the palette on
    save pays for the extra frames inside the 600 KiB the tests hold each case to.
    """

    selected = [line for line in lines if line.strip()]
    header = _terminal_header(case_id)
    frames: list[_DemoFrame] = [_DemoFrame((_window(_case_brief(case_id)), INTRO_DURATION_MS))]

    for index in range(0, len(selected), 2):
        window = selected[index : index + 2]
        visible = selected[: index + len(window)]
        frame_lines = header + visible
        if len(_wrap_lines(frame_lines)) > MAX_LINES:
            frame_lines = header + selected[max(0, index - 14) : index + len(window)]
        frames.append(_DemoFrame((_window(frame_lines), COMMAND_DURATION_MS)))

    frames.append(_DemoFrame((_window(_case_outro(case_id)), OUTRO_DURATION_MS)))
    return frames


def _frame_height(frames: list[_DemoFrame]) -> int:
    """One height for every frame of a case, set by the tallest.

    Every frame of a GIF must share dimensions, so this is computed once per case rather
    than per frame -- but from the content, not from a constant that left a third of the
    terminal empty.
    """

    tallest = max((len(_wrap_lines(list(lines))) for lines, _ in frames), default=0)
    # CAPTION_STRIP keeps a clear band at the foot for the "verbatim output" label. With
    # only 40px of slack the last line of a full screen was drawn straight through it.
    return max(MIN_HEIGHT, PADDING_Y + 36 + tallest * LINE_HEIGHT + CAPTION_STRIP)


def _render_frame(lines: list[str], height: int, captured: frozenset[str]) -> Image.Image:
    image = Image.new("RGB", (WIDTH, height), "#15161d")
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle(
        (16, 16, WIDTH - 16, height - 16), radius=24, fill="#101116", outline="#303541", width=2
    )
    draw.ellipse((44, 40, 60, 56), fill="#ff5f57")
    draw.ellipse((70, 40, 86, 56), fill="#ffbd2e")
    draw.ellipse((96, 40, 112, 56), fill="#28c840")
    draw.text(
        (150, 35), "trustweave — declaration-consistency review", fill="#abb2bf", font=_font(18)
    )
    y = PADDING_Y + 36
    gutter_spans: list[tuple[int, int]] = []
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
        # A line that run-case.sh actually emitted is marked by the gutter, not by a
        # banner in the body. The distinction is the one the README documents.
        if line.strip() in captured:
            gutter_spans.append((y - 3, y + LINE_HEIGHT - 5))
        draw.text((PADDING_X + 14, y), line, fill=color, font=_font(18))
        y += LINE_HEIGHT

    if gutter_spans:
        top = min(span[0] for span in gutter_spans)
        bottom = max(span[1] for span in gutter_spans)
        draw.rounded_rectangle(
            (PADDING_X - 2, top, PADDING_X + 1, bottom), radius=2, fill="#3f7d74"
        )
        # Fixed spot at the foot of the terminal. Positioning it under the last marked
        # line drew it on top of whatever came next.
        draw.rounded_rectangle(
            (PADDING_X - 2, height - 56, PADDING_X + 1, height - 44), radius=2, fill="#3f7d74"
        )
        draw.text((PADDING_X + 14, height - 58), CAPTURED_CAPTION, fill="#5d6672", font=_font(14))
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
    walkthrough_lines = (
        _case_brief(case_id)
        + ["", CAPTURED_OUTPUT_START]
        + output_lines
        + [CAPTURED_OUTPUT_END, ""]
        + _case_outro(case_id)
    )
    CASE_DIR.mkdir(parents=True, exist_ok=True)
    _write_cast(case_id, walkthrough_lines, CASE_DIR / f"{case_id}.cast")
    frames = _frames(output_lines, case_id)
    height = _frame_height(frames)
    # Which lines came out of run-case.sh, so the gutter can mark exactly those.
    captured = frozenset(line.strip() for line in output_lines if line.strip())
    rendered = [_render_frame(lines, height, captured) for lines, _ in frames]
    durations = [duration for _, duration in frames]
    # A terminal screen uses about a dozen colours, so quantising to a small shared
    # palette is nearly lossless here and is what brings a case inside its 600 KiB
    # budget. Saving full-colour frames and hoping `optimize` would cover it did not:
    # narrowing the canvas and revealing fewer lines per frame both helped and the files
    # were still 650 KiB.
    palette = rendered[0].convert("P", palette=Image.ADAPTIVE, colors=PALETTE_COLORS)
    quantised = [frame.quantize(palette=palette, dither=Image.Dither.NONE) for frame in rendered]
    quantised[0].save(
        CASE_DIR / f"{case_id}.gif",
        save_all=True,
        append_images=quantised[1:],
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
