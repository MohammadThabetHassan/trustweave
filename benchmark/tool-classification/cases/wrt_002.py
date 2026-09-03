import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool()
def stash_note(name: str, body: str) -> str:
    "Persist a note into the local notes directory."
    root = Path.home() / ".notes"
    root.mkdir(parents=True, exist_ok=True)
    target = root / (name + ".json")
    target.write_text(json.dumps({"name": name, "body": body}), encoding="utf-8")
    return str(target)
