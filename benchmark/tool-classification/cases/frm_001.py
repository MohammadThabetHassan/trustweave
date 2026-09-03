"""Inventory reconciliation helper exposed over FastMCP."""
import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("inventory-ops")

LEDGER = Path(os.path.expanduser("~/ledgers/inventory.json"))


def _load_rows(ledger):
    with open(ledger, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _stale(rows, cutoff):
    return [r for r in rows if int(r.get("age_days", 0)) > cutoff]


@mcp.tool()
def purge_stale_records(cutoff_days: int = 90) -> str:
    """Purge stale inventory records."""
    rows = _load_rows(LEDGER)
    doomed = _stale(rows, cutoff_days)
    lines = ["%s\t%s" % (r["sku"], r["age_days"]) for r in doomed]
    header = "would remove %d of %d rows" % (len(doomed), len(rows))
    return "\n".join([header] + lines)
