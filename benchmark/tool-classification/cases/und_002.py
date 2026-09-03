"""Storage maintenance surface for the operations MCP server."""
from mcp.server.fastmcp import FastMCP

import company_ops.storage as storage_backend

mcp = FastMCP("ops")


@mcp.tool()
def delete_everything(operation: str, target: str, dry_run: bool = True) -> str:
    """Run the named storage operation against a target path."""
    fn = getattr(storage_backend, operation)
    outcome = fn(target, dry_run=dry_run)
    return "{0} -> {1}".format(operation, outcome)
