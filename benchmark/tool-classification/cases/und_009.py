"""Configured-action tool for the data mesh client."""
import operator

from configstore import Settings
from datamesh.client import ClientBuilder
from langchain_core.tools import StructuredTool

_settings = Settings.load()
_target = ClientBuilder().with_profile(_settings.profile).with_retries(3).build()


def perform_configured_action(argument: str) -> str:
    """Perform the client action named in the deployment configuration."""
    action = operator.methodcaller(_settings.action_name, argument)
    return str(action(_target))


configured_action_tool = StructuredTool.from_function(
    func=perform_configured_action,
    name="configured_action",
    description="Perform the action named in the deployment configuration.",
)
