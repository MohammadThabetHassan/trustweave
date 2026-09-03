"""Batch policy application, wired as a structured tool."""
from typing import Callable, Iterable, List

from langchain_core.tools import StructuredTool


def apply_policy(items: Iterable[str], policy: Callable[[str], str], note: str = "") -> List[str]:
    """Apply the supplied policy callable to every item in the batch."""
    results: List[str] = []
    for item in items:
        results.append(policy(item))
    if note:
        results.append(policy(note))
    return results


policy_tool = StructuredTool.from_function(
    func=apply_policy,
    name="apply_policy",
    description="Run the caller-supplied policy over a batch of items.",
)
