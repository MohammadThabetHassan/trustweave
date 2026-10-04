"""The XACML comparison's instrument, on the parts that need no Java: what it reads, what it
builds, and its statistics. The Java side is exercised by its development run."""

from __future__ import annotations

import importlib.util
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _module() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "xacml_criteria_study", ROOT / "scripts" / "xacml_criteria_study.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules["xacml_criteria_study"] = module
    specification.loader.exec_module(module)
    return module


study = _module()
NS = study.NS
SUBJECT = "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
RESOURCE = "urn:oasis:names:tc:xacml:3.0:attribute-category:resource"


def _policy(target: str = "", condition: str = "") -> str:
    rule_target = f"<Target>{target}</Target>" if target else ""
    rule_condition = f"<Condition>{condition}</Condition>" if condition else ""
    return (
        f'<Policy xmlns="{NS}" PolicyId="p" Version="1.0" RuleCombiningAlgId='
        '"urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides"><Target/>'
        f'<Rule RuleId="r" Effect="Permit">{rule_target}{rule_condition}</Rule></Policy>'
    )


def _match(function: str, value: str, attribute: str = "role", kind: str = "string") -> str:
    return (
        f'<AnyOf><AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:{function}">'
        f'<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#{kind}">{value}</AttributeValue>'
        f'<AttributeDesignator AttributeId="{attribute}" Category="{SUBJECT}" '
        f'DataType="http://www.w3.org/2001/XMLSchema#{kind}" MustBePresent="false"/>'
        "</Match></AllOf></AnyOf>"
    )


AMOUNT_OVER_100 = (
    '<Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:integer-greater-than">'
    '<Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:integer-one-and-only">'
    f'<AttributeDesignator AttributeId="amount" Category="{RESOURCE}" '
    'DataType="http://www.w3.org/2001/XMLSchema#integer" MustBePresent="true"/></Apply>'
    '<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#integer">100</AttributeValue>'
    "</Apply>"
)


def test_the_protocol_is_the_registered_one_and_names_eleven_policies() -> None:
    assert study._lf_sha256(study.PROTOCOL) == study.PROTOCOL_SHA256
    eligible, excluded = study.population()
    assert len(eligible) == 11 and len(excluded) == 9
    assert "kmarket-blue-policy.xml" in eligible and "pluto3.xml" in eligible
    assert excluded["HL7.xml"] == "outside the fragment: it reads the clock"
    assert excluded["itrust3-40.xml"].startswith("over the cap")


def test_an_eligible_policy_yields_its_literals_thresholds_a_fresh_value_and_absence() -> None:
    policy = study.Policy(_policy(_match("string-equal", "admin"), AMOUNT_OVER_100))
    assert policy.reasons == []
    assert [kind for kind, _ in policy.atoms] == ["match", "condition"]
    candidates = policy.candidates()
    role = (SUBJECT, "role", study.STRING)
    amount = (RESOURCE, "amount", study.INTEGER)
    assert candidates[role] == ["admin", "tw-fresh-value", None]
    assert candidates[amount] == ["99", "100", "101", "1101", None]
    assert policy.cells() == 15


@pytest.mark.parametrize(
    ("fragment", "reason"),
    [
        (_match("string-regexp-match", "a.*"), "match string-regexp-match"),
        (
            AMOUNT_OVER_100.replace("integer-one-and-only", "integer-subtract"),
            "nested integer-subtract",
        ),
        (
            '<Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-equal">'
            '<AttributeSelector Path="//x" Category="c" '
            'DataType="http://www.w3.org/2001/XMLSchema#string" MustBePresent="false"/>'
            '<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">a</AttributeValue>'
            "</Apply>",
            "an AttributeSelector",
        ),
    ],
)
def test_what_the_witness_space_cannot_decide_is_named(fragment: str, reason: str) -> None:
    text = (
        _policy(target=fragment) if fragment.startswith("<AnyOf>") else _policy(condition=fragment)
    )
    assert reason in study.Policy(text).reasons


def test_a_request_carries_its_values_escaped_and_the_attribute_no_policy_reads() -> None:
    role = (SUBJECT, "role", study.STRING)
    amount = (RESOURCE, "amount", study.INTEGER)
    request = study.request_xml({role: ['a<b"&'], amount: []})
    root = ET.fromstring(request)
    values = [v.text for v in root.iter(f"{{{NS}}}AttributeValue")]
    assert values == ['a<b"&', "unread"]
    assert "amount" not in request
    assert request.count("\n") == 0

    xpa_request = f'<Request xmlns="{NS}"><Attributes Category="{SUBJECT}"></Attributes></Request>'
    added = study.with_unread(xpa_request)
    assert added.count("urn:trustweave:attribute:unread") == 1 and added.endswith("</Request>")


def test_an_atom_is_its_own_one_rule_policy() -> None:
    policy = study.Policy(_policy(_match("string-equal", "admin"), AMOUNT_OVER_100))
    for index, (kind, element) in enumerate(policy.atoms):
        text = study.atom_policy(kind, element, index)
        root = ET.fromstring(text)
        rules = list(root.iter(f"{{{NS}}}Rule"))
        assert len(rules) == 1 and rules[0].get("Effect") == "Permit"
        part = "Match" if kind == "match" else "Condition"
        assert len(list(root.iter(f"{{{NS}}}{part}"))) == 1


def test_the_sign_flip_test_is_exact_and_holm_is_monotone() -> None:
    # Five positive differences: only the all-positive and all-negative patterns are as extreme.
    assert study.exact_sign_flip([0.1, 0.2, 0.3, 0.4, 0.5]) == pytest.approx(2 / 32)
    assert study.exact_sign_flip([0.0, 0.0]) == 1.0
    adjusted = study.holm({"a": 0.01, "b": 0.04, "c": 0.03})
    assert adjusted == pytest.approx({"a": 0.03, "c": 0.06, "b": 0.06})
