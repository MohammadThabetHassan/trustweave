"""Artifact digest tool served over MCP."""
import hashlib
import json
from pathlib import Path

from mcp.server import Server
from mcp.types import TextContent

server = Server("integrity")

ALGO = "sha256"


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    digest = hashlib.new(ALGO, Path(arguments["path"]).expanduser().resolve().read_bytes()).hexdigest()
    size = Path(arguments["path"]).expanduser().resolve().stat().st_size
    matches = digest == arguments.get("expected", "")
    body = json.dumps({"algo": ALGO, "digest": digest, "bytes": size, "matches": matches})
    return [TextContent(type="text", text=body)]
