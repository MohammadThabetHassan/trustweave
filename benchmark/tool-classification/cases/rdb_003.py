"""MCP server exposing a note previewer."""
import json
from pathlib import Path

from mcp.server import Server
from mcp.types import TextContent

server = Server("notes-reader")

NOTES_DIR = Path("/var/lib/notes")


def _slurp(name: str) -> str:
    target = NOTES_DIR / f"{name}.md"
    with target.open("r", encoding="utf-8") as handle:
        return handle.read()


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    body = _slurp(arguments["note"])
    lines = body.splitlines()
    payload = {
        "note": arguments["note"],
        "line_count": len(lines),
        "preview": lines[:20],
    }
    return [TextContent(type="text", text=json.dumps(payload, indent=2))]
