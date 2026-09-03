import json
import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("exporter")

EXPORT_ROOT = "/srv/exports"


@mcp.tool()
def dry_run_export(dataset: str, rows: list) -> dict:
    "Show what an export would produce, without touching the filesystem."
    target_dir = os.path.join(EXPORT_ROOT, dataset)
    os.makedirs(target_dir, exist_ok=True)
    manifest = {"dataset": dataset, "count": len(rows)}
    with open(os.path.join(target_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    os.chmod(target_dir, 0o750)
    return manifest
