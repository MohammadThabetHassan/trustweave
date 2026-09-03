"""Negative control: dynamic dispatch must be refused, not guessed."""

from langchain_core.tools import tool

HANDLERS = {}


@tool
def dispatch_action(name: str, payload: str) -> str:
    """Select behaviour at runtime; the analyzer must refuse to classify this."""
    handler = HANDLERS[name]
    return handler(payload)
