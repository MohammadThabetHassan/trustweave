"""Every checked-in GIF is held to a budget, including the one that was not.

The fourteen declaration-consistency cases have had a size budget and a test enforcing it
for some time. `demo/research-assistant/demo.gif` had neither, and it drifted to 1,345 KiB
in 24-bit colour -- more than twice what any case is allowed -- without anything noticing.
That is the failure this file exists to prevent: not the size itself, which is a judgement
call, but a repository asset that nothing measures.

Re-encoding it to a 16-colour palette brought it to 892 KiB with the same frames, the same
dimensions and the same per-frame timing, which `scripts/optimise_demo_gif.py` verifies
each time it runs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# The research-assistant demo is the flagship walkthrough: 44 frames of dense output
# against a case's 15, so it gets a larger allowance than a case does -- but an allowance.
RESEARCH_ASSISTANT_MAX_BYTES = 1_000 * 1024

# Nothing outside the two demo directories should be shipping an animation at all.
KNOWN_GIF_DIRECTORIES = (
    ROOT / "demo" / "declaration-consistency" / "cases",
    ROOT / "demo" / "research-assistant",
)


def _tracked_gifs() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("*.gif")
        if not any(part in {".git", "mutants", "outputs", ".feynman"} for part in path.parts)
    )


def test_the_research_assistant_demo_stays_within_its_budget() -> None:
    path = ROOT / "demo" / "research-assistant" / "demo.gif"

    assert path.is_file()
    size = path.stat().st_size
    assert size <= RESEARCH_ASSISTANT_MAX_BYTES, (
        f"{path.name} is {size / 1024:.0f} KiB, above the "
        f"{RESEARCH_ASSISTANT_MAX_BYTES / 1024:.0f} KiB budget; re-encode it with "
        f"scripts/optimise_demo_gif.py rather than raising the number"
    )


def test_the_research_assistant_demo_is_palette_encoded() -> None:
    """24-bit colour is what made it 1,345 KiB, and a terminal render never needs it."""

    from PIL import Image

    path = ROOT / "demo" / "research-assistant" / "demo.gif"
    with Image.open(path) as animation:
        assert animation.mode == "P", "a GIF of a terminal should be palette encoded"
        palette = animation.getpalette() or []
    assert len(palette) // 3 <= 256


def test_every_checked_in_gif_lives_in_a_directory_that_has_a_budget() -> None:
    """A new animation somewhere unmeasured is how the last one grew unnoticed."""

    strays = [
        path
        for path in _tracked_gifs()
        if not any(path.is_relative_to(directory) for directory in KNOWN_GIF_DIRECTORIES)
    ]

    assert strays == [], "these GIFs are in no directory covered by a size budget: " + ", ".join(
        str(path.relative_to(ROOT)) for path in strays
    )


@pytest.mark.parametrize("path", _tracked_gifs(), ids=lambda path: path.name)
def test_no_checked_in_gif_is_absurdly_large(path: Path) -> None:
    """A backstop with a generous limit, so a doubling is caught even in a new directory."""

    assert path.stat().st_size <= 1_500 * 1024, (
        f"{path.relative_to(ROOT)} is {path.stat().st_size / 1024:.0f} KiB"
    )
