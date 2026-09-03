"""Sales reporting tool backed by a read-only SQLite warehouse."""
import sqlite3

from langchain_core.tools import StructuredTool

DB_PATH = "/srv/reporting/warehouse.db"

QUERY = (
    "SELECT sku, units, revenue_cents FROM sales "
    "WHERE region = ? ORDER BY revenue_cents DESC LIMIT ?"
)


def _fetch(region, limit):
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    try:
        cursor = conn.cursor()
        cursor.execute(QUERY, (region, int(limit)))
        return cursor.fetchall()
    finally:
        conn.close()


def top_skus(region: str, limit: int = 10) -> str:
    """Best selling SKUs for a region."""
    rows = []
    for sku, units, cents in _fetch(region, limit):
        rows.append(f"{sku}\t{units}\t{cents / 100:.2f}")
    return "\n".join(rows) or "no rows"


top_skus_tool = StructuredTool.from_function(
    func=top_skus,
    name="top_skus",
    description="Best selling SKUs in a region.",
)
