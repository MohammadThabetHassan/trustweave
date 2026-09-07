"""Assertion strength for the bounded source intake.

`tests/test_code_discovery.py` covers what this module does. These tests cover what it
*says*: the refusal messages, which tuple a file lands in, the reason recorded against a
skipped file, and the exact boundary of each limit. Mutation testing showed those were
unasserted -- 96% line coverage with a 70% kill rate on this module -- so a change that
swapped a reason code, dropped a message, or moved a limit by one byte passed the suite.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trustweave import code_sources
from trustweave.code_sources import (
    MAX_SOURCE_FILE_BYTES,
    SkippedFile,
    SourceFile,
    collect_python_sources,
)
from trustweave.models import ValidationError


def _write(directory: Path, name: str, body: str) -> Path:
    target = directory / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    return target


# ---------------------------------------------------------------------------------------
# Every refusal says which rule was broken
# ---------------------------------------------------------------------------------------


def test_a_symlinked_root_says_that_is_why(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(ValidationError, match="symlinked source path"):
        collect_python_sources(link)


def test_a_missing_root_says_it_does_not_exist(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="does not exist"):
        collect_python_sources(tmp_path / "absent")


def test_a_non_python_file_says_it_is_not_a_module(tmp_path: Path) -> None:
    target = _write(tmp_path, "notes.txt", "text")

    with pytest.raises(ValidationError, match="not a Python module"):
        collect_python_sources(target)


def test_a_target_that_is_neither_file_nor_directory_is_named_as_such(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    import os

    os.mkfifo(fifo)

    with pytest.raises(ValidationError, match="neither a file nor a directory"):
        collect_python_sources(fifo)


def test_exceeding_the_total_byte_limit_names_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The accumulator and its boundary, without writing 32 MiB to disk."""

    monkeypatch.setattr(code_sources, "MAX_TOTAL_SOURCE_BYTES", 20)
    _write(tmp_path, "a.py", "x = 1\n")
    _write(tmp_path, "b.py", "y = 2\n")
    _write(tmp_path, "c.py", "z = 3\n")
    _write(tmp_path, "d.py", "w = 4\n")

    with pytest.raises(ValidationError, match="byte limit for one review"):
        collect_python_sources(tmp_path)


def test_the_total_byte_limit_is_not_tripped_by_reaching_it_exactly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`>` not `>=`: a tree that exactly fills the budget is analyzed, not refused."""

    body = "x = 1\n"
    monkeypatch.setattr(code_sources, "MAX_TOTAL_SOURCE_BYTES", len(body.encode("utf-8")) * 2)
    _write(tmp_path, "a.py", body)
    _write(tmp_path, "b.py", body)

    assert len(collect_python_sources(tmp_path).files) == 2


# ---------------------------------------------------------------------------------------
# A single file lands in the right tuple, under the right name
# ---------------------------------------------------------------------------------------


def test_a_readable_single_file_is_reported_as_a_file(tmp_path: Path) -> None:
    target = _write(tmp_path, "agent.py", "x = 1\n")

    collection = collect_python_sources(target)

    assert collection.root_name == "agent.py"
    assert [entry.relative_path for entry in collection.files] == ["agent.py"]
    assert collection.skipped == ()


def test_an_oversized_single_file_is_reported_as_skipped_with_its_name(tmp_path: Path) -> None:
    """The record must carry which file was skipped, not only that one was."""

    target = _write(tmp_path, "big.py", "# padding\n" * (MAX_SOURCE_FILE_BYTES // 10 + 1))

    collection = collect_python_sources(target)

    assert collection.root_name == "big.py"
    assert collection.files == ()
    assert collection.skipped == (SkippedFile("big.py", "file_exceeds_size_limit"),)


def test_a_file_of_exactly_the_size_limit_is_analyzed(tmp_path: Path) -> None:
    """`>` not `>=`: the limit is inclusive, and a boundary test is the only way to say so."""

    target = _write(tmp_path, "edge.py", "#" * MAX_SOURCE_FILE_BYTES)

    collection = collect_python_sources(target)

    assert [type(entry) for entry in collection.files] == [SourceFile]
    assert collection.skipped == ()


def test_a_file_that_is_not_utf8_is_skipped_with_that_reason(tmp_path: Path) -> None:
    target = tmp_path / "latin.py"
    target.write_bytes(b"x = '\xff\xfe'\n")

    collection = collect_python_sources(tmp_path)

    assert collection.skipped == (SkippedFile("latin.py", "file_is_not_utf8"),)
    assert collection.files == ()


# ---------------------------------------------------------------------------------------
# The walk keeps going past what it declines
# ---------------------------------------------------------------------------------------


def test_a_non_python_file_does_not_stop_the_walk(tmp_path: Path) -> None:
    """A `continue` turned into a `break` would silently truncate the review."""

    _write(tmp_path, "aaa.txt", "text")
    _write(tmp_path, "zzz.py", "x = 1\n")

    assert [entry.relative_path for entry in collect_python_sources(tmp_path).files] == ["zzz.py"]


def test_a_symlinked_module_does_not_stop_the_walk(tmp_path: Path) -> None:
    real = _write(tmp_path, "real.py", "x = 1\n")
    (tmp_path / "aaa_link.py").symlink_to(real)

    found = [entry.relative_path for entry in collect_python_sources(tmp_path).files]

    assert found == ["real.py"]


def test_a_skipped_file_does_not_stop_the_walk(tmp_path: Path) -> None:
    """The oversized file sorts first; the readable one after it must still be collected."""

    _write(tmp_path, "aaa.py", "# padding\n" * (MAX_SOURCE_FILE_BYTES // 10 + 1))
    _write(tmp_path, "zzz.py", "x = 1\n")

    collection = collect_python_sources(tmp_path)

    assert [entry.relative_path for entry in collection.files] == ["zzz.py"]
    assert [entry.relative_path for entry in collection.skipped] == ["aaa.py"]


def test_a_pruned_directory_does_not_stop_the_walk(tmp_path: Path) -> None:
    _write(tmp_path, "__pycache__/cached.py", "x = 1\n")
    _write(tmp_path, "zzz.py", "y = 2\n")

    assert [entry.relative_path for entry in collect_python_sources(tmp_path).files] == ["zzz.py"]


# ---------------------------------------------------------------------------------------
# Output ordering is part of the contract: an artifact must be reproducible
# ---------------------------------------------------------------------------------------


def test_files_are_reported_in_path_order(tmp_path: Path) -> None:
    for name in ("z.py", "a.py", "m/inner.py"):
        _write(tmp_path, name, "x = 1\n")

    found = [entry.relative_path for entry in collect_python_sources(tmp_path).files]

    assert found == sorted(found) == ["a.py", "m/inner.py", "z.py"]


def test_skipped_files_are_reported_in_path_order(tmp_path: Path) -> None:
    oversized = "# padding\n" * (MAX_SOURCE_FILE_BYTES // 10 + 1)
    for name in ("z.py", "a.py"):
        _write(tmp_path, name, oversized)

    found = [entry.relative_path for entry in collect_python_sources(tmp_path).skipped]

    assert found == ["a.py", "z.py"]


def test_a_nested_module_is_addressed_relative_to_the_root(tmp_path: Path) -> None:
    """An absolute path in the artifact would disclose where the checkout lives."""

    _write(tmp_path, "pkg/sub/mod.py", "x = 1\n")

    collection = collect_python_sources(tmp_path)

    assert [entry.relative_path for entry in collection.files] == ["pkg/sub/mod.py"]
    assert collection.root_name == tmp_path.name


def test_exceeding_the_file_count_limit_names_the_count_and_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`>` not `>=`: a tree holding exactly the limit is analyzed, one more is refused."""

    monkeypatch.setattr(code_sources, "MAX_SOURCE_FILES", 2)
    for name in ("a.py", "b.py"):
        _write(tmp_path, name, "x = 1\n")

    assert len(collect_python_sources(tmp_path).files) == 2

    _write(tmp_path, "c.py", "x = 1\n")

    with pytest.raises(ValidationError, match="3 Python files, above the 2 file limit"):
        collect_python_sources(tmp_path)
