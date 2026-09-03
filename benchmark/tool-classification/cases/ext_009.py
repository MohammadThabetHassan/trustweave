"""CRM account lookup tool."""
from mcp.server import Server
from requests import Session as S

server = Server("crm-tools")

BASE = "https://crm.example.io/api"


@server.call_tool()
async def lookup_account(name: str, arguments: dict) -> dict:
    """Fetch the account record for an account id."""
    sess = S()
    sess.headers.update({"Accept": "application/json"})
    resp = sess.get(BASE + "/accounts/" + str(arguments["account_id"]), timeout=15)
    return resp.json()
