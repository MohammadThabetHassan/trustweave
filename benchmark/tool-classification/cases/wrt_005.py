import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("cache")

CACHE = Path("/var/cache/agent/index.json")


@mcp.tool()
def lookup_entry(key: str, refresh: bool = False) -> dict:
    "Look up a cached entry, optionally refreshing its hit counter."
    data = json.loads(CACHE.read_text(encoding="utf-8"))
    entry = data.get(key, {"hits": 0})
    if refresh:
        entry = dict(entry, hits=entry.get("hits", 0) + 1)
        data[key] = entry
        CACHE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return entry
