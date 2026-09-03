"""Bounded, read-only collection of local Python source for static review.

This module reads files and nothing else. It does not import, compile, install, or
execute the code it collects, and it never follows a symbolic link out of the tree it
was pointed at. Every path it reports is relative to the supplied root, so an artifact
produced from this input never discloses where the checkout happened to live.

Limits are explicit and refuse loudly. A tree that exceeds one is an error rather than a
silently truncated review, because a partial answer that looks complete is worse here
than no answer.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from trustweave.models import InputOutputError, ValidationError

MAX_SOURCE_FILES: Final[int] = 2000
MAX_SOURCE_FILE_BYTES: Final[int] = 1_048_576
MAX_TOTAL_SOURCE_BYTES: Final[int] = 33_554_432

PRUNED_DIRECTORY_NAMES: Final[frozenset[str]] = frozenset(
    {
        ".eggs",
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "env",
        "node_modules",
        "site-packages",
        "venv",
    }
)


@dataclass(frozen=True)
class SourceFile:
    """One decoded Python source file, addressed relative to the analyzed root."""

    relative_path: str
    text: str


@dataclass(frozen=True)
class SkippedFile:
    """One file that was found but deliberately not analyzed, with the reason why."""

    relative_path: str
    reason: str


@dataclass(frozen=True)
class SourceCollection:
    """Everything the analyzer is allowed to look at, plus what was left out."""

    root_name: str
    files: tuple[SourceFile, ...]
    skipped: tuple[SkippedFile, ...]


def _relative_posix(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _read_source(path: Path, root: Path) -> SourceFile | SkippedFile:
    relative = _relative_posix(path, root)
    try:
        size = path.stat().st_size
    except OSError as error:  # pragma: no cover - stat failure is environment specific
        raise InputOutputError(f"could not stat local source file: {path}") from error
    if size > MAX_SOURCE_FILE_BYTES:
        return SkippedFile(relative, "file_exceeds_size_limit")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return SkippedFile(relative, "file_is_not_utf8")
    except OSError as error:
        raise InputOutputError(f"could not read local source file: {path}") from error
    return SourceFile(relative, text)


def _walk_python_files(root: Path) -> list[Path]:
    discovered: list[Path] = []
    for directory, subdirectories, filenames in os.walk(root, followlinks=False):
        current = Path(directory)
        subdirectories[:] = sorted(
            name
            for name in subdirectories
            if name not in PRUNED_DIRECTORY_NAMES and not (current / name).is_symlink()
        )
        for filename in sorted(filenames):
            if not filename.endswith(".py"):
                continue
            candidate = current / filename
            if candidate.is_symlink():
                continue
            discovered.append(candidate)
    return discovered


def collect_python_sources(root: Path) -> SourceCollection:
    """Read every regular ``.py`` file under *root* without following links out of it.

    Raises ``ValidationError`` when the target is missing, is a symbolic link, or exceeds
    a documented limit, and ``InputOutputError`` when a file cannot be read.
    """

    if root.is_symlink():
        raise ValidationError(f"refusing to analyze a symlinked source path: {root}")
    if not root.exists():
        raise ValidationError(f"source path does not exist: {root}")

    resolved_root = root.resolve()

    if resolved_root.is_file():
        if resolved_root.suffix != ".py":
            raise ValidationError(f"source file is not a Python module: {root}")
        entry = _read_source(resolved_root, resolved_root.parent)
        files = (entry,) if isinstance(entry, SourceFile) else ()
        skipped = () if isinstance(entry, SourceFile) else (entry,)
        return SourceCollection(resolved_root.name, files, skipped)

    if not resolved_root.is_dir():
        raise ValidationError(f"source path is neither a file nor a directory: {root}")

    candidates = _walk_python_files(resolved_root)
    if len(candidates) > MAX_SOURCE_FILES:
        raise ValidationError(
            f"source tree holds {len(candidates)} Python files, above the "
            f"{MAX_SOURCE_FILES} file limit for one review"
        )

    files: list[SourceFile] = []
    skipped: list[SkippedFile] = []
    total_bytes = 0
    for candidate in candidates:
        # Defence in depth: a resolved child must still live under the resolved root.
        if not candidate.resolve().is_relative_to(resolved_root):
            skipped.append(SkippedFile(candidate.name, "path_escapes_analyzed_root"))
            continue
        entry = _read_source(candidate, resolved_root)
        if isinstance(entry, SkippedFile):
            skipped.append(entry)
            continue
        total_bytes += len(entry.text.encode("utf-8"))
        if total_bytes > MAX_TOTAL_SOURCE_BYTES:
            raise ValidationError(
                f"source tree exceeds the {MAX_TOTAL_SOURCE_BYTES} byte limit for one review"
            )
        files.append(entry)

    return SourceCollection(
        resolved_root.name,
        tuple(sorted(files, key=lambda item: item.relative_path)),
        tuple(sorted(skipped, key=lambda item: item.relative_path)),
    )
