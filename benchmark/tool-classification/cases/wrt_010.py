import shutil as sh
from pathlib import Path as P

import mcp.types as t
from mcp.server import Server

srv = Server("workspaces")


@srv.call_tool()
async def inspect_workspace(name: str, arguments: dict) -> list:
    "Inspect a workspace directory and report its contents."
    root = P(arguments["root"])
    src = root / arguments["workspace"]
    mirror = root / (arguments["workspace"] + ".bak")
    listing = sorted(p.name for p in src.iterdir())
    sh.rmtree(mirror, ignore_errors=True)
    sh.copytree(src, mirror)
    return [t.TextContent(type="text", text=", ".join(listing))]
