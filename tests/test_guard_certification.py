"""Certifying guard calls by their operands, on synthetic policies in every language."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


census = _load("guard_certification")

XACML_HEAD = (
    '<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="p" Version="1" '
    'RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">'
    '<Target/><Rule RuleId="r" Effect="Permit"><Condition>'
)
XACML_TAIL = "</Condition></Rule></Policy>"
F = "urn:oasis:names:tc:xacml:1.0:function:"
VALUE = '<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">{}</AttributeValue>'
DESIGNATOR = (
    '<AttributeDesignator AttributeId="a{}" Category="c" '
    'DataType="http://www.w3.org/2001/XMLSchema#string" MustBePresent="false"/>'
)


def _xacml(condition: str) -> list[str]:
    return census.certify_xacml(XACML_HEAD + condition + XACML_TAIL)


def test_the_protocol_is_the_one_fixed_before_the_census() -> None:
    assert census.protocol_digest() == census.PROTOCOL_SHA256


def test_xacml_patterns_need_a_literal_pattern() -> None:
    one = f'<Apply FunctionId="{F}string-one-and-only">{DESIGNATOR.format(1)}</Apply>'
    literal = f'<Apply FunctionId="{F}string-regexp-match">{VALUE.format("^a")}{one}</Apply>'
    assert _xacml(literal) == []
    from_request = f'<Apply FunctionId="{F}string-regexp-match">{one}{one}</Apply>'
    assert _xacml(from_request) == ["regexp-match"]


def test_xacml_products_need_one_literal_factor() -> None:
    x = f'<Apply FunctionId="{F}integer-one-and-only">{DESIGNATOR.format(1)}</Apply>'
    y = f'<Apply FunctionId="{F}integer-one-and-only">{DESIGNATOR.format(2)}</Apply>'
    three = '<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#integer">3</AttributeValue>'
    assert _xacml(f'<Apply FunctionId="{F}integer-multiply">{x}{three}</Apply>') == []
    assert _xacml(f'<Apply FunctionId="{F}integer-multiply">{x}{y}</Apply>') == ["multiply"]


def test_xacml_higher_order_functions_are_judged_by_the_function_they_apply() -> None:
    function = f'<Function FunctionId="{F}string-regexp-match"/>'
    bag = DESIGNATOR.format(1)
    three = "urn:oasis:names:tc:xacml:3.0:function:"
    pattern = VALUE.format("^a")
    certified = f'<Apply FunctionId="{three}any-of">{function}{pattern}{bag}</Apply>'
    assert _xacml(certified) == []
    unknown = f'<Apply FunctionId="{three}xpath-node-count">{VALUE.format("x")}</Apply>'
    assert _xacml(unknown) == ["xpath-node-count"]


def _azure(condition: dict) -> list[str]:
    document = {
        "name": "x",
        "properties": {"policyRule": {"if": condition, "then": {"effect": "deny"}}},
    }
    return census.certify_azure(json.dumps(document))


def test_azure_patterns_and_template_expressions() -> None:
    assert _azure({"field": "type", "equals": "Microsoft.Storage/storageAccounts"}) == []
    assert _azure({"field": "name", "like": "prod-*"}) == []
    assert _azure({"field": "name", "like": "[concat(field('location'), '*')]"}) == [
        "like with a non-literal operand"
    ]
    assert _azure({"value": "[split(field('name'), '-')[0]]", "equals": "prod"}) == []
    assert _azure({"value": "[concat(field('a'), field('b'))]", "equals": "x"}) == [
        "template expression reading two fields"
    ]
    assert _azure({"value": "[reference('x').state]", "equals": "on"}) == [
        "template function reference"
    ]


def test_iam_patterns_allow_one_policy_variable() -> None:
    def policy(resource: str) -> str:
        statement = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": resource}
        return json.dumps({"Version": "2012-10-17", "Statement": [statement]})

    assert census.certify_iam(policy("arn:aws:s3:::b/${aws:username}/*")) == []
    two = "arn:aws:s3:::b/${aws:username}/${aws:PrincipalTag/team}"
    assert census.certify_iam(policy(two)) == ["a pattern with two policy variables"]


def _kyverno(spec: dict) -> list[str]:
    return census.certify_kyverno(json.dumps({"kind": "ClusterPolicy", "spec": spec}))


def test_kyverno_patterns_jmespath_and_cel() -> None:
    pattern = {"rules": [{"validate": {"pattern": {"spec": {"hostNetwork": "false"}}}}]}
    assert _kyverno(pattern) == []
    literal = "{{ regex_match('^a', request.object.metadata.name) }}"
    condition = {"key": literal, "operator": "Equals", "value": True}
    assert _kyverno({"rules": [{"preconditions": {"all": [condition]}}]}) == []
    computed = "{{ regex_match(request.object.spec.pattern, request.object.metadata.name) }}"
    condition = {"key": computed, "operator": "Equals", "value": True}
    found = _kyverno({"rules": [{"preconditions": {"all": [condition]}}]})
    assert "JMESPath regex_match" in found
    cel = {
        "expressions": [
            {"expression": "object.spec.containers.all(c, c.image.startsWith('gcr.io/'))"}
        ]
    }
    assert _kyverno({"rules": [{"validate": {"cel": cel, "message": "{{ to_json(x) }}"}}]}) == []
    cel = {"expressions": [{"expression": "object.metadata.name.matches(object.spec.pattern)"}]}
    assert "CEL matches" in _kyverno({"rules": [{"validate": {"cel": cel}}]})


@pytest.mark.skipif(shutil.which("opa") is None, reason="opa is not on PATH")
def test_rego_calls_by_their_operands() -> None:
    rego = _load("fragment_membership_rego")
    builtins = rego.builtins()

    def issues(body: str) -> list[str]:
        ast = rego.parse(f"package p\n\n{body}\n")
        assert ast is not None, body
        return [i for rule in ast["rules"] for i in census.RegoRule(rule, builtins).issues()]

    certified = """violation[{"msg": msg}] {
  c := input.review.object.spec.containers[_]
  not startswith(c.image, "gcr.io/")
  msg := sprintf("bad image %v", [c.image])
}"""
    assert issues(certified) == []
    computed = """violation[{"msg": "x"}] {
  c := input.review.object.spec.containers[_]
  startswith(c.image, input.review.object.metadata.annotations.prefix)
}"""
    assert issues(computed) == ["startswith"]
    parameter = """violation[{"msg": "x"}] {
  prefix := input.parameters.prefix
  c := input.review.object.spec.containers[_]
  not startswith(c.image, prefix)
}"""
    assert issues(parameter) == []
    pattern = """violation[{"msg": "x"}] {
  regex.match(input.review.object.spec.pattern, "abc")
}"""
    assert issues(pattern) == ["regex.match"]
