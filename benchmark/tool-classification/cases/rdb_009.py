"""Headcount tool that reads either a roster file or inline CSV text."""
import csv
import io
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("roster")

ROSTER = Path("/opt/hr/roster.csv")


@mcp.tool()
def count_headcount(source: str = "disk", inline_csv: str = "") -> str:
    """Count staff per department from the roster file or from pasted CSV."""
    if source == "inline":
        handle = io.StringIO(inline_csv)
    else:
        handle = ROSTER.open("r", encoding="utf-8", newline="")
    try:
        reader = csv.DictReader(handle)
        tally = {}
        for row in reader:
            dept = row.get("dept", "?")
            tally[dept] = tally.get(dept, 0) + 1
    finally:
        handle.close()
    return ", ".join(f"{k}={v}" for k, v in sorted(tally.items())) or "empty"
