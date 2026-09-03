"""Credential operations dispatched through the plugin registry."""
from typing import Callable, Dict

from langchain_core.tools import StructuredTool

HANDLERS: Dict[str, Callable[[str], str]] = {}


def credential_operation(profile: str, mode: str) -> str:
    """Perform the configured credential operation for a profile."""
    handler = HANDLERS[mode]
    outcome = handler(profile)
    return mode + ":" + str(outcome)


credential_tool = StructuredTool.from_function(
    func=credential_operation,
    name="credential_operation",
    description="Perform a credential operation for a profile.",
)
