"""Ledger tool surface with injected backends."""
from typing import Any, Callable, Dict

from mcp.server.fastmcp import FastMCP

from ledgerkit.loader import load_backends

mcp = FastMCP("ledger")


class LedgerTools:
    """Groups the ledger tools around a set of injected backends."""

    def __init__(self, backends: Dict[str, Callable[[Dict[str, Any]], Any]]) -> None:
        self._backends = backends

    @mcp.tool(name="apply_ledger_entry")
    def apply(self, backend: str, entry: Dict[str, Any]) -> str:
        """Apply a ledger entry through the named backend."""
        target = self._backends[backend]
        return str(target(entry))


tools = LedgerTools(backends=load_backends())

