"""Service status tools for the platform MCP server."""
import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("status-tools")


def _fetch(path):
    client = httpx.Client(base_url="https://status.example.net", timeout=8.0)
    with client as session:
        return session.get(path).text


@mcp.tool()
def service_health(service: str) -> str:
    """Report the current health string for a service."""
    body = _fetch("/health/" + service)
    return body.strip()
