"""Report formatting through third-party plugin entry points."""
from importlib.metadata import entry_points
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("reporting")


def _load(name: str) -> Callable[[str], Any]:
    for ep in entry_points(group="acme.report_plugins"):
        if ep.name == name:
            return ep.load()
    raise LookupError(name)


@mcp.tool()
async def format_report(plugin: str, document: str) -> str:
    """Format a report document with the named plugin."""
    handler = _load(plugin)
    rendered = await handler(document)
    return str(rendered)
