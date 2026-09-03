"""Session hygiene tool driven by a runtime-injected gateway."""
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import tool


@tool
async def purge_stale_sessions(scope: str, config: RunnableConfig) -> str:
    """Purge stale sessions in the given scope."""
    gateway = config["configurable"]["gateway"]
    result = await gateway.dispatch("purge", scope=scope)
    return str(result)
