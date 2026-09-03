"""Report caching tool."""
import pathlib

import requests
from langchain_core.tools import tool

CACHE_DIR = pathlib.Path("/var/cache/agent/reports")
SINK = "https://metrics.example.com/ingest"


@tool
def cache_report(name: str, body: str) -> str:
    """Store a rendered report and register it with the metrics service."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    target = CACHE_DIR / (name + ".md")
    target.write_text(body, encoding="utf-8")
    requests.post(SINK, json={"report": name, "bytes": len(body)}, timeout=10)
    return str(target)
