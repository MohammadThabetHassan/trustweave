"""Resolving the string enum an MCP server names its tools with.

Naming tools with a `str, Enum` is the idiomatic pattern in the reference servers, so a
declared name is often `GitTools.STATUS` rather than `"git_status"`. Without resolving the
member the declared names are invisible and the artifact reports the handler function
instead of the names the model is actually offered.

`_enum_string_members` reads those members and `_declared_tool_name` resolves one argument
through them. Both are pure functions over a parsed module, and the end-to-end discovery
tests reach them through fixtures whose tools are found by other means, so neither had a
test that failed when the resolution stopped working.
"""

from __future__ import annotations

import ast

import pytest

from trustweave.code_analysis import _declared_tool_name, _enum_string_members


def _members(source: str) -> dict[str, str]:
    return _enum_string_members(ast.parse(source))


# ---------------------------------------------------------------------------------------
# Which classes are read, and which assignments inside them count
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("base", ["Enum", "StrEnum", "IntEnum"])
def test_members_are_read_from_each_recognised_enum_base(base: str) -> None:
    assert _members(f"class GitTools({base}):\n    STATUS = 'git_status'\n") == {
        "GitTools.STATUS": "git_status"
    }


def test_a_dotted_enum_base_is_recognised_by_its_final_name() -> None:
    """`enum.Enum` is the same base as `Enum`."""

    assert _members("class GitTools(enum.Enum):\n    STATUS = 'git_status'\n") == {
        "GitTools.STATUS": "git_status"
    }


def test_a_str_and_enum_class_is_read() -> None:
    """The idiomatic spelling carries two bases and only one of them is the enum."""

    assert _members("class GitTools(str, Enum):\n    STATUS = 'git_status'\n") == {
        "GitTools.STATUS": "git_status"
    }


def test_a_class_that_is_not_an_enum_contributes_nothing() -> None:
    assert _members("class Config:\n    STATUS = 'git_status'\n") == {}


def test_a_non_string_member_is_not_a_tool_name() -> None:
    assert _members("class GitTools(Enum):\n    STATUS = 1\n") == {}


def test_a_multiple_assignment_target_is_skipped() -> None:
    """Two names bound to one literal do not name one tool."""

    assert _members("class GitTools(Enum):\n    A = B = 'git_status'\n") == {}


def test_every_member_of_one_enum_is_read() -> None:
    members = _members(
        "class GitTools(str, Enum):\n"
        "    STATUS = 'git_status'\n"
        "    DIFF = 'git_diff'\n"
        "    LOG = 'git_log'\n"
    )

    assert members == {
        "GitTools.STATUS": "git_status",
        "GitTools.DIFF": "git_diff",
        "GitTools.LOG": "git_log",
    }


def test_members_of_several_enums_are_keyed_by_their_own_class() -> None:
    members = _members(
        "class GitTools(str, Enum):\n    STATUS = 'git_status'\n"
        "class FileTools(str, Enum):\n    STATUS = 'file_status'\n"
    )

    assert members == {"GitTools.STATUS": "git_status", "FileTools.STATUS": "file_status"}


def test_a_nested_enum_is_not_read_as_a_module_level_one() -> None:
    """Only module-level classes are read, so a locally defined enum is left alone."""

    assert (
        _members("def build():\n    class GitTools(Enum):\n        STATUS = 'git_status'\n") == {}
    )


# ---------------------------------------------------------------------------------------
# Resolving one declared name through those members
# ---------------------------------------------------------------------------------------


def test_a_literal_tool_name_is_taken_directly() -> None:
    assert _declared_tool_name(ast.Constant("git_status"), {}) == "git_status"


def test_an_enum_member_is_resolved_to_its_string() -> None:
    members = {"GitTools.STATUS": "git_status"}
    argument = ast.parse("GitTools.STATUS", mode="eval").body

    assert _declared_tool_name(argument, members) == "git_status"


def test_an_enum_member_value_is_resolved_to_the_same_string() -> None:
    """`GitTools.STATUS.value` names the same tool as `GitTools.STATUS`."""

    members = {"GitTools.STATUS": "git_status"}
    argument = ast.parse("GitTools.STATUS.value", mode="eval").body

    assert _declared_tool_name(argument, members) == "git_status"


def test_an_unknown_enum_member_resolves_to_nothing() -> None:
    argument = ast.parse("GitTools.MISSING", mode="eval").body

    assert _declared_tool_name(argument, {"GitTools.STATUS": "git_status"}) is None


def test_no_argument_resolves_to_nothing() -> None:
    assert _declared_tool_name(None, {"GitTools.STATUS": "git_status"}) is None


def test_a_computed_argument_resolves_to_nothing() -> None:
    argument = ast.parse("choose()", mode="eval").body

    assert _declared_tool_name(argument, {"GitTools.STATUS": "git_status"}) is None
