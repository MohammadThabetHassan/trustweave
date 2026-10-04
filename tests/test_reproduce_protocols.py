"""The pre-registration check: every artifact's recorded protocol hash names a protocol held."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _module() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "check_protocols", ROOT / "reproduce" / "check_protocols.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules["check_protocols"] = module
    specification.loader.exec_module(module)
    return module


check = _module()


def test_every_committed_artifact_names_a_committed_protocol() -> None:
    assert check.main(["--docs", str(ROOT / "docs")]) == 0
    assert len(check.recorded(ROOT / "docs")) >= 10


def test_a_protocol_edited_after_its_study_is_reported(tmp_path: Path) -> None:
    protocol = tmp_path / "TOY_PROTOCOL.md"
    protocol.write_text("the plan\n", encoding="utf-8")
    digest = next(iter(check.protocol_hashes(tmp_path)))
    (tmp_path / "toy-study-v1.json").write_text(json.dumps({"protocol_sha256": digest}), "utf-8")
    assert check.main(["--docs", str(tmp_path)]) == 0

    protocol.write_text("the plan, changed after the run\n", encoding="utf-8")
    assert check.main(["--docs", str(tmp_path)]) == 1


def test_line_endings_do_not_change_a_protocol_hash(tmp_path: Path) -> None:
    unix = tmp_path / "A_PROTOCOL.md"
    unix.write_bytes(b"one\ntwo\n")
    first = set(check.protocol_hashes(tmp_path))
    shutil.copy(unix, tmp_path / "unused.txt")
    unix.write_bytes(b"one\r\ntwo\r\n")
    assert set(check.protocol_hashes(tmp_path)) == first
