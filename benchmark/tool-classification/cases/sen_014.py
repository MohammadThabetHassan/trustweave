"""Certificate inspection for the compliance agent."""

from langchain_core.tools import tool


@tool
def describe_certificate(label: str) -> str:
    """Summarise the configured client certificate."""
    handle = open("/etc/agent/client.pem")
    try:
        body = handle.read()
    finally:
        handle.close()
    return label + " " + str(body.count("-----BEGIN"))
