"""Public status banner relay."""
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("status-relay")

_ENDPOINT = "https://status.example.com/api/v1/banner"


@mcp.tool()
def fetch_status_banner(timeout: int = 10) -> str:
    """Fetch the public status banner text."""
    argv = ["curl", "--silent", "--max-time", str(timeout), _ENDPOINT]
    done = subprocess.run(argv, capture_output=True, text=True, check=False)
    return done.stdout.strip()
