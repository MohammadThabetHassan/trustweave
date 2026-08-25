import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
PROVENANCE_PATH = (
    ROOT / "examples" / "evaluation-corpus" / "declaration-completeness" / "provenance.json"
)
VERIFIER_PATH = ROOT / "scripts" / "verify_declaration_completeness_provenance.py"
ATTRIBUTES_PATH = ROOT / ".gitattributes"


def _verifier_module() -> ModuleType:
    """Load the standalone provenance verifier without altering package boundaries."""

    specification = importlib.util.spec_from_file_location(
        "declaration_completeness_provenance", VERIFIER_PATH
    )
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def _provenance() -> dict[str, object]:
    document = json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def test_fixture_provenance_matches_every_benchmark_input() -> None:
    verifier = _verifier_module()

    assert verifier.verify_provenance() == []


def test_fixture_provenance_rejects_exact_file_digest_drift(tmp_path: Path) -> None:
    verifier = _verifier_module()
    provenance = _provenance()
    files = provenance["files"]
    assert isinstance(files, list)
    first = files[0]
    assert isinstance(first, dict)
    first["sha256"] = "0" * 64
    path = tmp_path / "provenance.json"
    path.write_text(json.dumps(provenance), encoding="utf-8")

    failures = verifier.verify_provenance(path)

    assert any("Fixture digest mismatch" in failure for failure in failures)


def test_fixture_provenance_rejects_missing_benchmark_input(tmp_path: Path) -> None:
    verifier = _verifier_module()
    provenance = _provenance()
    files = provenance["files"]
    assert isinstance(files, list)
    files.pop()
    path = tmp_path / "provenance.json"
    path.write_text(json.dumps(provenance), encoding="utf-8")

    failures = verifier.verify_provenance(path)

    assert any("must exactly match benchmark definition inputs" in failure for failure in failures)


def test_fixture_provenance_forces_platform_stable_lf_fixture_checkouts() -> None:
    attributes = ATTRIBUTES_PATH.read_text(encoding="utf-8")

    assert "examples/evaluation-corpus/declaration-completeness/** text eol=lf" in attributes


def test_fixture_provenance_verifier_is_local_and_does_not_write_inputs() -> None:
    source = VERIFIER_PATH.read_text(encoding="utf-8")

    for prohibited in (
        "subprocess",
        "requests",
        "httpx",
        "urllib",
        "socket",
        "os.environ",
        "getenv",
        "write_text",
        "write_bytes",
    ):
        assert prohibited not in source
