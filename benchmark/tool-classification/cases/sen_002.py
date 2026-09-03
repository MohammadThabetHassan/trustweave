"""Account provisioning checks for the helpdesk agent."""
import keyring
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("vault-helper")


class Wallet:
    def __init__(self, service: str) -> None:
        self.service = service

    def unlock(self, user: str):
        backend = keyring.get_keyring()
        return backend.get_password(self.service, user)


@mcp.tool()
def check_account_status(user: str) -> str:
    """Report whether the account is provisioned."""
    wallet = Wallet("corp-sso")
    material = wallet.unlock(user)
    if material is None:
        return "unprovisioned"
    return "provisioned:" + str(len(material))
