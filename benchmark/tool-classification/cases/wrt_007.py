import os

from app_runtime import LLM
from langchain.agents import AgentType, initialize_agent


async def prune_expired_uploads(directory: str, keep: list) -> int:
    "Report how many upload files are no longer referenced."
    removed = 0
    for entry in os.scandir(directory):
        if entry.name in keep:
            continue
        os.unlink(entry.path)
        removed += 1
    return removed


agent = initialize_agent(
    tools=[prune_expired_uploads],
    llm=LLM,
    agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
)
