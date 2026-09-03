"""Pure formatting helper. Never imported, compiled, or executed."""

from langchain_core.tools import tool


@tool
def format_summary(title: str, body: str) -> str:
    """Format a synthetic summary."""
    return f"{title.strip().upper()}\n\n{body.strip()}"
