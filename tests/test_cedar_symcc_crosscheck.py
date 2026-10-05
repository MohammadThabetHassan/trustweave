"""The SymCC check's reading of a counterexample, its replay, and its classes.

The two counterexamples below are what `cedar symcc equivalent` (cedar-policy-cli 4.12.0, cvc5
1.3.1) printed for a synthetic schema and policy written to exercise every form a value takes:
a set, a record with a key that is not a name, an entity reference, two extension values, an
ancestor, a tag, a string escape, and a request whose principal is its resource.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _module() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "cedar_symcc_crosscheck", ROOT / "scripts" / "cedar_symcc_crosscheck.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules["cedar_symcc_crosscheck"] = module
    specification.loader.exec_module(module)
    return module


check = _module()

POLICY = r"""@id("dev")
permit (principal in App::Group::"g\"q", action == App::Action::"read", resource is App::Doc)
when {
  principal.level > 3 && principal.labels.contains("x\ty") && principal.profile.dept == "eng" &&
  principal.profile["odd key"] == 7 && resource.owner == principal.manager &&
  principal.limit.greaterThan(decimal("1.5")) && principal.addr.isInRange(ip("10.0.0.0/8")) &&
  principal.hasTag("t") && principal.getTag("t") == "v" && context.origin.isLoopback() &&
  context.n < 0 && context.meta.a
};
"""

RICH = r"""✗ Policy sets are equivalent: DOES NOT HOLD
  Counterexample found:
principal: App::User::"", action: App::Action::"read", resource: App::Doc::""
context: {meta: {a: true}, n: -1, origin: ip("127.255.255.255/32")}
entities: [
  App::User::"A" in [App::Group::"g\"q"] {
    addr: ip("10.255.255.255/32"),
    labels: ["x\ty"],
    level: 9223372036854775807,
    limit: decimal("922337203685477.5807"),
    manager: App::User::"A",
    profile: {"dept": "eng", "odd key": 7},
  } tags {
    t: "v",
  },
  App::User::"" in [App::Group::"g\"q"] {
    addr: ip("10.255.255.255/32"),
    labels: ["x\ty"],
    level: 9223372036854775807,
    limit: decimal("922337203685477.5807"),
    manager: App::User::"A",
    profile: {"dept": "eng", "odd key": 7},
  } tags {
    t: "v",
  },
  App::Action::"read",
  App::Doc::"" {
    owner: App::User::"A",
  },
  App::Group::"g\"q",
]
"""

SELF = r"""✗ Policy sets are equivalent: DOES NOT HOLD
  Counterexample found:
principal: App::User::"alice", action: App::Action::"read", resource: App::User::"alice"
context: {meta: {a: false}, n: 0, origin: ip("0.0.0.0/32")}
entities: [
  App::User::"alice" {
    addr: ip("0.0.0.0/32"),
    labels: [],
    level: 0,
    limit: decimal("0.0000"),
    manager: App::User::"",
    profile: {"dept": "", "odd key": 0},
  },
  App::Action::"read",
]
"""


# What the command printed for a population file whose policies read a datetime: the value is
# an expression, an offset from a date, rather than one constructor call.
DATETIME = r"""✗ Policy sets are equivalent: DOES NOT HOLD
  Counterexample found:
principal: User::"", action: Action::"github.read", resource: Resource::""
context: {call: {agent: {id: ""}, principal: {attrs: {department: "", team: ""}, id: "", type: ""}, resource: {type: ""}, tool: {name: ""}}, now: (datetime("1970-01-01")).offset(duration("0ms"))}
entities: [
  Action::"github.read",
  Resource::"",
  User::"",
]
"""  # noqa: E501 - the command's own line


def _entity(entities: list[dict], kind: str, name: str) -> dict:
    return next(e for e in entities if e["uid"]["__entity"] == {"type": kind, "id": name})


def test_the_registration_hashes_name_the_committed_files() -> None:
    assert check._lf_sha256(check.PROTOCOL) == check.PROTOCOL_SHA256
    assert check._lf_sha256(check.CANDIDATES) == check.CANDIDATES_SHA256


def test_every_form_a_value_takes_is_read() -> None:
    request, entities = check.parse_counterexample(RICH.replace("\n", "\r\n"))
    assert request["principal"] == 'App::User::""'
    assert request["action"] == 'App::Action::"read"'
    assert request["resource"] == 'App::Doc::""'
    assert request["context"] == {
        "meta": {"a": True},
        "n": -1,
        "origin": {"__extn": {"fn": "ip", "arg": "127.255.255.255/32"}},
    }
    assert len(entities) == 5
    alice = _entity(entities, "App::User", "A")
    assert alice["parents"] == [{"__entity": {"type": "App::Group", "id": 'g"q'}}]
    assert alice["attrs"] == {
        "addr": {"__extn": {"fn": "ip", "arg": "10.255.255.255/32"}},
        "labels": ["x\ty"],
        "level": 9223372036854775807,
        "limit": {"__extn": {"fn": "decimal", "arg": "922337203685477.5807"}},
        "manager": {"__entity": {"type": "App::User", "id": "A"}},
        "profile": {"dept": "eng", "odd key": 7},
    }
    assert alice["tags"] == {"t": "v"}
    assert _entity(entities, "App::Action", "read") == {
        "uid": {"__entity": {"type": "App::Action", "id": "read"}},
        "attrs": {},
        "parents": [],
    }
    assert _entity(entities, "App::Doc", "")["attrs"] == {
        "owner": {"__entity": {"type": "App::User", "id": "A"}}
    }


def test_a_datetime_is_passed_on_as_the_call_that_denotes_it() -> None:
    request, entities = check.parse_counterexample(DATETIME)
    assert request["context"]["now"] == {
        "__extn": {
            "fn": "offset",
            "args": [
                {"__extn": {"fn": "datetime", "arg": "1970-01-01"}},
                {"__extn": {"fn": "duration", "arg": "0ms"}},
            ],
        }
    }
    assert request["context"]["call"]["principal"]["attrs"] == {"department": "", "team": ""}
    assert len(entities) == 3

    pytest.importorskip("cedarpy")
    import cedarpy._internal as internal

    text = 'permit (principal, action, resource) when { context.now < datetime("1970-01-02") };'
    original = json.loads(internal.policies_to_json_str(text))
    flipped = json.loads(internal.policies_to_json_str(text.replace("permit", "forbid")))
    verdict, facts = check.replay(original, flipped, DATETIME)
    assert (verdict, facts["file"], facts["mutant"]) == ("confirmed", "Allow", "Deny")


def test_a_request_whose_principal_is_its_resource_is_read_as_one_entity() -> None:
    request, entities = check.parse_counterexample(SELF)
    assert request["principal"] == request["resource"] == 'App::User::"alice"'
    assert [e["uid"]["__entity"]["id"] for e in entities] == ["alice", "read"]


@pytest.mark.parametrize(
    "text",
    [
        "✓ Policy sets are equivalent: VERIFIED\n",
        SELF.replace("level: 0,", "level: <unknown>,"),
        SELF.replace('ip("0.0.0.0/32")', 'ip"0.0.0.0/32"', 1),
        SELF.replace('ip("0.0.0.0/32")', 'ip("0.0.0.0/32"', 1),
        SELF.replace('"alice"', '"al\\qice"', 1),
    ],
)
def test_text_that_cannot_be_read_is_unreadable(text: str) -> None:
    with pytest.raises(check.Unreadable):
        check.parse_counterexample(text)


def test_a_request_entity_is_written_as_cedar_reads_it() -> None:
    assert check._cedar_uid(("App::User", 'a"b\\c')) == 'App::User::"a\\"b\\\\c"'
    assert check._cedar_uid(("User", "x\ny")) == 'User::"x\\u{a}y"'
    reader = check._Reader('"a\\u{1F600}b"')
    assert reader.string() == "a\U0001f600b"


def test_each_result_of_the_command_is_named() -> None:
    assert check.outcome(0, "✓ Policy sets are equivalent: VERIFIED\n", "") == "verified"
    assert check.outcome(0, RICH, "") == "counterexample"
    failed = "Error: Analysis failed\n  Failed to compile policy set 2\n  type error"
    assert check.outcome(1, "", failed) == "mutant does not compile"
    assert check.outcome(1, "", failed.replace("set 2", "set 1")) == "file does not compile"
    assert check.outcome(1, "", "Verification failed: solver returned unknown") == "no answer"


def test_the_classes_follow_the_protocol() -> None:
    every = ["verified", "verified"]
    partly = ["verified", "mutant does not compile"]
    found = ["counterexample", "verified"]
    assert check.classify("equivalent", every, []) == "not refuted, every environment verified"
    assert check.classify("equivalent", partly, []) == "not refuted, partly checked"
    assert check.classify("equivalent", ["no answer"], []) == "unchecked"
    assert check.classify("equivalent", found, ["confirmed"]) == "refuted"
    # A counterexample the engine does not confirm never refutes, nor counts as verified.
    for replay in ("unconfirmed", "unreplayed"):
        assert check.classify("equivalent", found, [replay]) == "not refuted, partly checked"
        assert check.classify("live", found, [replay]) == "counterexample not confirmed"
    assert check.classify("live", found, ["unreplayed", "confirmed"]) == "live under the schema"
    assert check.classify("live", every, []) == "equivalent under the schema"
    assert check.classify("live", partly, []) == "equivalent where checked"
    assert check.classify("live", ["wall-clock limit"], []) == "unchecked"
    assert check._operator("negate_condition0[policy0]") == "negate_condition"
    assert check._operator("==_to_!=@c0left[policy3]") == "==_to_!="
    assert check._operator('literal_to_"ADMIN"@c0right[policy1]') == "literal_to"


def test_the_engine_confirms_a_counterexample_only_when_it_separates() -> None:
    pytest.importorskip("cedarpy")
    import cedarpy._internal as internal

    original = json.loads(internal.policies_to_json_str(POLICY))
    flipped = json.loads(internal.policies_to_json_str(POLICY.replace("permit (", "forbid (", 1)))
    verdict, facts = check.replay(original, flipped, RICH)
    assert (verdict, facts["file"], facts["mutant"]) == ("confirmed", "Allow", "Deny")
    assert facts["principal_is_resource"] is False
    verdict, facts = check.replay(original, original, RICH)
    assert verdict == "unconfirmed"
    verdict, facts = check.replay(original, flipped, RICH.replace("level: 9", "level: <unknown>"))
    assert verdict == "unreplayed"
