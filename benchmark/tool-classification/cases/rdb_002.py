"""Retention planning tool. Produces a plan, never touches storage."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("retention-planner")

RETENTION_DAYS = {"audit": 3650, "debug": 7, "session": 30}


def _plan_line(bucket, doomed, days):
    return f"{bucket}: {doomed} rows exceed the {days}-day window"


@mcp.tool()
def delete_records(bucket: str, row_count: int) -> str:
    """Describe what a purge WOULD remove. Nothing is removed here."""
    days = RETENTION_DAYS.get(bucket, 90)
    keep = max(0, row_count - (row_count * days) // 4000)
    doomed = row_count - keep
    report = [_plan_line(bucket, doomed, days), f"retained: {keep}", f"ratio: {doomed / max(row_count, 1):.3f}"]
    return "\n".join(report)
