"""Support-desk record helper exposed to the customer agent."""
from __future__ import annotations

from typing import Any, Callable, Dict

from langchain_core.tools import tool

from acme_backoffice.handlers import build_handler_table

_TABLE: Dict[str, Callable[[str], Any]] = build_handler_table()


def _resolve(action: str) -> Callable[[str], Any]:
    try:
        return _TABLE[action]
    except KeyError as exc:
        raise ValueError("unknown action: %s" % action) from exc


@tool
def readonly_lookup(action: str, record_id: str) -> str:
    """Look up a customer record using the configured backoffice action."""
    handler = _resolve(action)
    outcome = handler(record_id)
    return "%s:%s" % (action, outcome)
