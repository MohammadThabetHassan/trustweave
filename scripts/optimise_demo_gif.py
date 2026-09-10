"""Re-encode a checked-in demo GIF without changing what it shows.

`demo/research-assistant/demo.gif` was 1{,}345 KiB in 24-bit colour while every
declaration-consistency case is held to 600 KiB. The difference was not deliberate: the
case GIFs have a test enforcing a budget and this one did not, so it grew unchecked.

The content is a recording of a real run and is not regenerable from anything in this
repository -- the README says the GIF comes from `./run.sh`, but the encoding step was
never scripted. So this does not re-render anything. It reads the frames that are there,
quantises them to a shared palette, and writes them back with the same size, the same
frame count and the same per-frame durations. A terminal recording uses a few dozen
colours, so the palette costs nothing visible and the file roughly halves.

    python scripts/optimise_demo_gif.py demo/research-assistant/demo.gif [--check]

`--check` reports what would change and writes nothing, which is what CI wants.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageSequence

# Measured rather than guessed. The source frames hold 48 distinct colours, so palettes of
# 64 and 128 produce identical output (1{,}110 KiB) and only 16 makes a real difference
# (892 KiB). Glyph edges were checked at 2x zoom against the original before settling here:
# a terminal render has no gradients for a small palette to band.
PALETTE_COLORS = 16


def frames_and_durations(path: Path) -> tuple[list[Image.Image], list[int]]:
    """Every frame as RGB, with the duration each is shown for."""

    with Image.open(path) as animation:
        frames = [frame.convert("RGB") for frame in ImageSequence.Iterator(animation)]
    durations: list[int] = []
    with Image.open(path) as animation:
        try:
            while True:
                durations.append(int(animation.info.get("duration", 0)))
                animation.seek(animation.tell() + 1)
        except EOFError:
            pass
    return frames, durations


def reencode(path: Path, *, check: bool) -> tuple[int, int]:
    """(bytes before, bytes after). Writes nothing when `check` is set."""

    before = path.stat().st_size
    frames, durations = frames_and_durations(path)
    if not frames:
        raise SystemExit(f"{path}: no frames")

    palette = frames[0].convert("P", palette=Image.ADAPTIVE, colors=PALETTE_COLORS)
    quantised = [frame.quantize(palette=palette, dither=Image.Dither.NONE) for frame in frames]

    # Pillow picks the encoder from the suffix, so a check run still writes a `.gif`.
    destination = path if not check else path.with_name(path.stem + ".check.gif")
    quantised[0].save(
        destination,
        save_all=True,
        append_images=quantised[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )
    after = destination.stat().st_size

    # The point of this script is that nothing about the recording changes, so verify it
    # rather than assert it: same dimensions, same frames, same timing.
    rewritten, rewritten_durations = frames_and_durations(destination)
    if len(rewritten) != len(frames):
        raise SystemExit(f"{path}: frame count changed {len(frames)} -> {len(rewritten)}")
    if rewritten_durations != durations:
        raise SystemExit(f"{path}: frame timing changed")
    if rewritten[0].size != frames[0].size:
        raise SystemExit(f"{path}: dimensions changed")

    if check:
        destination.unlink()
    return before, after


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gif", type=Path, nargs="+")
    parser.add_argument("--check", action="store_true", help="report only, write nothing")
    arguments = parser.parse_args(argv)

    for path in arguments.gif:
        before, after = reencode(path, check=arguments.check)
        saved = 100 * (before - after) / before if before else 0.0
        verb = "would be" if arguments.check else "is"
        print(
            f"{path}: {before / 1024:.0f} KiB {verb} {after / 1024:.0f} KiB "
            f"({saved:.0f}% smaller), frames and timing unchanged"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
