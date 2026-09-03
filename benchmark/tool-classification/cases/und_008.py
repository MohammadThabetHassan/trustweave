"""State synchronisation tool backed by a decorator registry.

Handlers register themselves from other modules in the package; this file
contains no registrations of its own.
"""
from typing import Any, Callable, Dict

from langchain_core.tools import tool

REGISTRY: Dict[str, Callable[[str, str], Any]] = {}


def register(name: str) -> Callable[[Callable[[str, str], Any]], Callable[[str, str], Any]]:
    """Decorator used by sibling modules to add handlers to REGISTRY."""

    def _wrap(fn: Callable[[str, str], Any]) -> Callable[[str, str], Any]:
        REGISTRY[name] = fn
        return fn

    return _wrap


@tool
def sync_state(op: str, key: str, value: str = "") -> str:
    """Synchronise one key using the registered operation handler."""
    handler = REGISTRY[op]
    return str(handler(key, value))
