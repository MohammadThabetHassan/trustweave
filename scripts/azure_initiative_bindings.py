"""Which Azure policy schemas the corpus itself instantiates, and how completely.

A definition with a parameter carrying no default determines no decision function, which is
why the membership procedure reports it as a schema rather than as a policy outside the
fragment. That reason is only worth giving if the instantiation exists somewhere, and for
Gatekeeper and Config Validator it plainly does: both corpora ship a Constraint for every
template. Azure's answer is less obvious, because the thing that supplies a definition's
parameters is a *policy set definition* -- an initiative -- listing the definitions it
includes and the parameter values it binds for each.

So this asks the question directly. For every definition the membership artifact reports as a
schema, does some built-in initiative bind its parameters, and does it bind the ones that had
no default? The second half is the one that matters: an initiative binding some other
parameter would leave the definition just as far from being a policy. The answer is recorded
rather than counted in prose, because the count had been quoted in the write-up beside a
denominator that a re-measurement moved, and nothing could have caught that.

Usage:
    python scripts/azure_initiative_bindings.py --corpus <azure-policy> [--json out.json]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
MEMBERSHIP = "fragment-membership-azure-wide-v1"

# Initiatives live here. A definition's own directory is `policyDefinitions`; the sibling
# holds the sets that include them.
SET_DIRECTORY = ("built-in-policies", "policySetDefinitions")


def _definition_id(reference: dict[str, Any]) -> str:
    """The identifier an initiative entry points at, which is the last segment of its id."""

    identifier = str(reference.get("policyDefinitionId") or "")
    return identifier.rstrip("/").rsplit("/", 1)[-1]


def bindings(corpus: Path) -> tuple[dict[str, set[str]], int]:
    """(definition identifier -> every parameter name an initiative binds, initiatives read)."""

    bound: dict[str, set[str]] = {}
    initiatives = 0
    directory = corpus.joinpath(*SET_DIRECTORY)
    if not directory.is_dir():
        return bound, initiatives
    for path in sorted(directory.rglob("*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(document, dict):
            continue
        references = (document.get("properties") or {}).get("policyDefinitions")
        if not isinstance(references, list):
            continue
        initiatives += 1
        for reference in references:
            if not isinstance(reference, dict):
                continue
            parameters = reference.get("parameters")
            if isinstance(parameters, dict) and parameters:
                bound.setdefault(_definition_id(reference), set()).update(parameters)
    return bound, initiatives


def measure(corpus: Path, docs: Path = DOCS) -> dict[str, Any]:
    artifact = json.loads((docs / f"{MEMBERSHIP}.json").read_text(encoding="utf-8"))
    # Selected by the evidence, not by the reported reason. A definition that is a schema and
    # also tests a related resource reports the second, because an assignment removes only the
    # first -- so keying on the reason string would have measured 120 definitions here and
    # called it the schema population when the population is 855.
    schemas = {
        entry["subject"]: entry["parameters_without_defaults"]
        for entry in artifact["policies"]
        if entry.get("parameters_without_defaults")
    }
    bound, initiatives = bindings(corpus)

    parameterised = sorted(name for name in schemas if bound.get(name))
    completed = sorted(
        name
        for name, missing in schemas.items()
        if set(missing) <= bound.get(name, set()) and bound.get(name)
    )
    return {
        "schema_version": "v1",
        "membership_artifact": MEMBERSHIP,
        "initiatives_read": initiatives,
        "definitions_an_initiative_binds": len(bound),
        "schemas": len(schemas),
        "schemas_an_initiative_parameterises": len(parameterised),
        "schemas_an_initiative_completes": len(completed),
        "schemas_left_uninstantiated": sorted(set(schemas) - set(parameterised)),
    }


def render(findings: dict[str, Any]) -> str:
    return (
        f"{findings['initiatives_read']} initiatives bind parameters for "
        f"{findings['definitions_an_initiative_binds']} definitions\n"
        f"  of {findings['schemas']} schemas, "
        f"{findings['schemas_an_initiative_parameterises']} are parameterised by an "
        f"initiative and {findings['schemas_an_initiative_completes']} have every "
        f"undefaulted parameter supplied\n"
        f"  {len(findings['schemas_left_uninstantiated'])} are left with no initiative "
        f"binding anything"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--docs", type=Path, default=DOCS)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)

    findings = measure(args.corpus, args.docs)
    print(render(findings))
    if args.json:
        args.json.write_text(
            json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
