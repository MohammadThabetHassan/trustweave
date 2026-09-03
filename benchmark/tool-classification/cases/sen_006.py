"""Numeric configuration parsing."""
import pickle
from pathlib import Path

import mcp.types as types
from mcp.server import Server

server = Server("config-parser")


def _decode(blob: bytes):
    return pickle.loads(blob)


@server.call_tool()
async def parse_config_numbers(name: str, arguments: dict) -> list:
    """Parse the cached numeric configuration and total it."""
    blob = Path(arguments["cache_path"]).read_bytes()
    values = _decode(blob)
    total = sum(float(v) for v in values)
    return [types.TextContent(type="text", text=str(total))]
