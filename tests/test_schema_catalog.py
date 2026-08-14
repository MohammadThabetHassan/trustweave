from __future__ import annotations

from trustweave.cli import EXIT_INVALID_INPUT, main


def test_schema_list_and_show_are_local_and_deterministic(capsys: object) -> None:
    assert main(["schema", "list"]) == 0
    listed = capsys.readouterr().out.splitlines()  # type: ignore[attr-defined]
    assert listed == sorted(listed)
    assert "policy-v1alpha2.schema.json" in listed
    assert "risk-baseline-v1alpha2.schema.json" in listed
    assert "risk-suppressions-v1alpha2.schema.json" in listed

    assert main(["schema", "show", "policy-v1alpha2.schema.json"]) == 0
    assert '"$id": "https://trustweave.dev/schemas/policy/v1alpha2"' in capsys.readouterr().out  # type: ignore[attr-defined]


def test_schema_show_rejects_unknown_names(capsys: object) -> None:
    assert main(["schema", "show", "../secret.json"]) == EXIT_INVALID_INPUT
    assert "Unknown checked-in schema" in capsys.readouterr().err  # type: ignore[attr-defined]
