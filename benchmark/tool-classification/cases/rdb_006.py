"""Async payload inspection tool."""
import json
from datetime import datetime, timedelta, timezone

from fastmcp import FastMCP

mcp = FastMCP("payload-inspector")


@mcp.tool()
async def inspect_event_payload(raw: str, offset_minutes: int = 0) -> str:
    """Parse a JSON event payload and describe its shape."""
    event = json.loads(raw)
    stamp = datetime.fromtimestamp(float(event.get("ts", 0)), tz=timezone.utc)
    shifted = stamp + timedelta(minutes=offset_minutes)
    return json.dumps(
        {
            "keys": sorted(event.keys()),
            "kind": event.get("kind", "unknown"),
            "observed_at": shifted.isoformat(),
            "widest_value": max((len(str(v)) for v in event.values()), default=0),
        },
        sort_keys=True,
    )
