"""The schema list the SymCC cross-check is pre-registered on: how it is ordered and read."""

from __future__ import annotations

import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def _module() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "cedar_schema_candidates", ROOT / "scripts" / "cedar_schema_candidates.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules["cedar_schema_candidates"] = module
    specification.loader.exec_module(module)
    return module


candidates = _module()


def test_candidates_are_taken_nearest_first() -> None:
    found = candidates.ordered(
        "app/policies/admin.cedar",
        [
            "z/schema.json",
            "app/schema.cedarschema",
            "app/policies/b.cedarschema",
            "schema.cedarschema",
            "app/policies/a.cedarschema",
            "app/policies/sub/schema.cedarschema",
        ],
    )
    assert found == [
        ("app/policies/a.cedarschema", "same directory"),
        ("app/policies/b.cedarschema", "same directory"),
        ("app/schema.cedarschema", "ancestor"),
        ("schema.cedarschema", "ancestor"),
        ("app/policies/sub/schema.cedarschema", "elsewhere"),
        ("z/schema.json", "elsewhere"),
    ]


def test_a_verified_permissions_export_is_read_unwrapped() -> None:
    inner = json.dumps({"App": {"entityTypes": {}, "actions": {}}})
    wrapped = json.dumps({"cedarJson": inner}).encode()
    assert candidates.schema_source(wrapped, "store/schema.json") == ("json", inner)
    assert candidates.schema_source(b"entity User;", "schema.cedarschema") == (
        "cedar",
        "entity User;",
    )
    assert candidates.schema_source(b"\xef\xbb\xbf{}", "s.cedarschema")[0] == "json"


def test_a_blob_is_named_as_git_names_it() -> None:
    # `printf 'hello\n' | git hash-object --stdin`
    assert candidates.git_blob_sha1(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"


def test_the_committed_list_covers_every_scored_file_and_stops_at_its_schema() -> None:
    listed = json.loads((DOCS / "cedar-schema-candidates-v1.json").read_text("utf-8"))
    study = json.loads((DOCS / "cedar-suite-strategy-study-v1.json").read_text("utf-8"))
    scored = sorted(k for k, v in study["files"].items() if v["status"] == "scored")
    assert [f["subject"] for f in listed["files"]] == scored

    with_schema = [f for f in listed["files"] if f["schema"]]
    for entry in listed["files"]:
        results = [c["result"] for c in entry["candidates"]]
        assert "validates" not in results[:-1]
        kinds = [candidates.KINDS.index(c["kind"]) for c in entry["candidates"]]
        assert kinds == sorted(kinds)
        if entry["schema"]:
            assert results[-1] == "validates"
            last = {k: v for k, v in entry["candidates"][-1].items() if k != "result"}
            assert last == entry["schema"]
            assert entry["environments"]
        else:
            assert not entry["environments"]
    summary = listed["summary"]
    assert summary["files"] == len(scored)
    assert summary["with a schema"] == len(with_schema)
    assert summary["schema found"] == dict(Counter(f["schema"]["kind"] for f in with_schema))
    assert summary["environments"] == sum(len(f["environments"]) for f in with_schema)
