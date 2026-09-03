"""Bridge that exposes dotted plugin paths as MCP tools."""
import importlib
from typing import Any, Dict, List

from mcp.server import Server
from mcp.types import TextContent, Tool

server = Server("plugin-bridge")


@server.list_tools()
async def list_tools() -> List[Tool]:
    return [
        Tool(
            name="plugin_bridge",
            description="Invoke a dotted plugin entry point.",
            inputSchema={"type": "object", "properties": {"name": {"type": "string"}}},
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    module_path, _, attr = name.rpartition(".")
    module = importlib.import_module(module_path)
    entry = getattr(module, attr)
    payload = entry(**arguments)
    return [TextContent(type="text", text=str(payload))]
