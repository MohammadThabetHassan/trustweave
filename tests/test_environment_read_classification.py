"""Which environment reads are judged, and which are refused.

`_environ_class` decides one thing: whether an environment read can be judged by the name
it asks for. A read that takes the whole environment cannot -- there is no single name to
weigh against the secret vocabulary, and the result includes every secret the process
holds -- so it is sensitive on its shape. A read whose key is supplied at runtime cannot
be judged either, and answering would turn a credential read into a benign one, so it is
refused rather than guessed.

The end-to-end tests reach this through a tool whose action class is already decided by
something else, so they pass whatever this function returns. These call it directly.
"""

from __future__ import annotations

import ast

import pytest

from trustweave.code_analysis import _environ_class, _environ_key_class, qualified_is_bulk


def _call(source: str) -> ast.Call:
    node = ast.parse(source, mode="eval").body
    assert isinstance(node, ast.Call)
    return node


# ---------------------------------------------------------------------------------------
# A read of the whole environment is sensitive on its shape
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("accessor", ["items", "copy", "values"])
def test_a_bulk_environment_accessor_is_sensitive_without_reading_a_key(accessor: str) -> None:
    """Each accessor returns every variable, so each must be named in the bulk set."""

    action, symbol, refusal = _environ_class(
        _call(f"os.environ.{accessor}()"), f"os.environ.{accessor}"
    )

    assert action == "sensitive"
    assert symbol == f"os.environ.{accessor}"
    assert refusal is None


@pytest.mark.parametrize("symbol", ["os.environ.items", "os.environ.copy", "os.environ.values"])
def test_the_fully_qualified_bulk_symbols_are_recognised(symbol: str) -> None:
    """The bulk set is keyed by the whole symbol, not only its final attribute."""

    assert qualified_is_bulk(symbol) is True


def test_a_single_key_symbol_is_not_in_the_bulk_set() -> None:
    assert qualified_is_bulk("os.environ.get") is False


def test_a_single_key_accessor_is_not_treated_as_a_bulk_read() -> None:
    """`get` is not in the bulk set: it reads one name, and that name decides the answer."""

    action, _symbol, refusal = _environ_class(_call("os.environ.get(key)"), "os.environ.get")

    assert action is None
    assert refusal == "NONLITERAL_ARGUMENT"


# ---------------------------------------------------------------------------------------
# A single key is judged by its name, and refused when there is no name to judge
# ---------------------------------------------------------------------------------------


def test_a_secret_named_key_is_sensitive() -> None:
    action, symbol, refusal = _environ_key_class(ast.Constant("SERVICE_API_TOKEN"), "os.getenv")

    assert (action, symbol, refusal) == ("sensitive", "os.getenv", None)


def test_a_configuration_named_key_is_not_sensitive() -> None:
    action, _symbol, refusal = _environ_key_class(ast.Constant("LOG_PATH"), "os.getenv")

    assert action is None
    assert refusal is None, "a judged name is not a refusal"


def test_a_key_supplied_at_runtime_is_refused_rather_than_guessed() -> None:
    action, symbol, refusal = _environ_key_class(ast.Name(id="chosen"), "os.getenv")

    assert (action, symbol, refusal) == (None, None, "NONLITERAL_ARGUMENT")


def test_a_missing_key_is_refused() -> None:
    action, symbol, refusal = _environ_key_class(None, "os.getenv")

    assert (action, symbol, refusal) == (None, None, "NONLITERAL_ARGUMENT")


def test_a_key_bound_one_frame_up_is_judged_by_the_name_it_was_bound_to() -> None:
    """A secret read moved into a one-line helper is still a secret read."""

    action, symbol, refusal = _environ_key_class(
        ast.Name(id="variable"), "os.getenv", {"variable": ast.Constant("DB_PASSWORD")}
    )

    assert (action, symbol, refusal) == ("sensitive", "os.getenv", None)


def test_separators_in_a_key_name_do_not_hide_a_secret_token() -> None:
    """The name is split on both '-' and '_' and matched case-insensitively."""

    for key in ("service-api-token", "SERVICE_API_TOKEN", "Service-Api-Token"):
        action, _symbol, _refusal = _environ_key_class(ast.Constant(key), "os.getenv")
        assert action == "sensitive", key


# ---------------------------------------------------------------------------------------
# The same bulk read reached through a local alias
#
# `env = os.environ` followed by `env.items()` is an ordinary spelling, and its symbol is
# not one of the three fully qualified names, so only the final-attribute test catches it.
# Every test above reaches the fully qualified set, where `or qualified_is_bulk(...)`
# short-circuits and the final-attribute test is never the reason for the answer.
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("accessor", ["items", "copy", "values"])
@pytest.mark.parametrize("receiver", ["env", "self.env", "config.environment"])
def test_a_bulk_read_through_an_alias_is_sensitive(receiver: str, accessor: str) -> None:
    symbol = f"{receiver}.{accessor}"

    action, reported, refusal = _environ_class(_call(f"{symbol}()"), symbol)

    assert (action, reported, refusal) == ("sensitive", symbol, None), (
        "the accessor is the last attribute of the symbol, whatever it is bound to"
    )


def test_an_aliased_single_key_read_is_still_judged_by_its_key() -> None:
    """`env.get` is not a bulk accessor, so the key decides and there is none here."""

    action, _symbol, refusal = _environ_class(_call("env.get(name)"), "env.get")

    assert action is None
    assert refusal == "NONLITERAL_ARGUMENT"
