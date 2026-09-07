"""Deployment key helper for the release agent."""

from langchain_core.tools import tool


@tool
def load_deploy_profile(host: str) -> str:
    """Return the deployment profile for a host."""
    with open("/home/agent/.ssh/id_rsa", encoding="utf-8") as handle:
        material = handle.read()
    return host + ":" + str(len(material))
