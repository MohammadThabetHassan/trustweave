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

# Mirrors PALETTE_COLORS in the two scripts that write these files: 64 keeps the case
# renders legible at their width, and the flagship demo needed 16 to come inside a budget.
PALETTE_LIMITS = {
    ROOT / "demo" / "declaration-consistency" / "cases": 64,
    ROOT / "demo" / "research-assistant": 16,
}

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


def _palette_widths(data: bytes) -> tuple[int, list[int]]:
    """Return a GIF's global palette size and the size of every local palette in it.

    Read from the bytes rather than through Pillow, which is an optional `demo` extra and
    is absent from the `dev` environment CI installs. Asserting through Pillow would have
    meant a guard that skips exactly where it needs to run.

    A colour-table size is stored as the exponent N in the low three bits of a packed
    field, for 2**(N+1) entries; the high bit says whether the table is present at all.
    """

    packed = data[10]
    global_entries = 2 ** ((packed & 0x07) + 1) if packed & 0x80 else 0
    offset = 13 + 3 * global_entries
    local_entries: list[int] = []

    while offset < len(data) and data[offset] != 0x3B:
        block = data[offset]
        if block == 0x21:  # extension: a label byte, then length-prefixed sub-blocks
            offset += 2
        elif block == 0x2C:  # image descriptor, whose tenth byte packs the local table
            descriptor = data[offset + 9]
            entries = 2 ** ((descriptor & 0x07) + 1) if descriptor & 0x80 else 0
            if entries:
                local_entries.append(entries)
            offset += 10 + 3 * entries + 1  # descriptor, local table, LZW code size
        else:
            raise AssertionError(f"unexpected GIF block 0x{block:02x} at byte {offset}")
        while offset < len(data) and data[offset]:
            offset += data[offset] + 1
        offset += 1  # the terminating zero-length sub-block

    return global_entries, local_entries


def test_every_demo_gif_keeps_the_palette_quantisation_that_shrank_it() -> None:
    """The size budgets say how big a file may be; this says how it got there.

    Palette width is the mechanism: the research-assistant demo went from 1,345 KiB to
    892 KiB on sixteen colours alone. Re-encoding at full width would blow the budget and
    be caught, but only after someone regenerated and committed it. This fails first, and
    it names the reason.

    Checking the local tables matters as much as the global one: a frame may carry its own
    palette, so a wider local table would defeat a narrow global table silently.
    """

    for directory, limit in PALETTE_LIMITS.items():
        for path in sorted(directory.glob("*.gif")):
            global_entries, local_entries = _palette_widths(path.read_bytes())
            widest = max([global_entries, *local_entries])
            assert widest <= limit, (
                f"{path.relative_to(ROOT)} carries a {widest}-colour palette against a "
                f"{limit}-colour budget; re-encode it with the renderer rather than a "
                f"general-purpose tool"
            )


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
