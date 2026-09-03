"""Low-level MCP server that fronts an operator-supplied action registry."""
import mcp.types as types
from mcp.server import Server

from corp_actions.registry import load_registry

server = Server("action-broker")

REGISTRY = load_registry()


@server.call_tool()
async def dispatch(name: str, arguments: dict) -> list:
    if name != "run_action":
        raise ValueError("unknown tool: " + name)
    verb = arguments["action"]
    handler = REGISTRY[verb]
    result = handler(**arguments.get("params", {}))
    return [types.TextContent(type="text", text=str(result))]
