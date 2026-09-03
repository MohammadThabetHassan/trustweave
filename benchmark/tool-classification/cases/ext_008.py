"""Support ticket triage agent."""
import anthropic
from langchain.agents import initialize_agent

_MODEL = "claude-sonnet-4-5"


def classify_ticket(text: str) -> str:
    """Assign a support ticket to a queue."""
    handle = anthropic.Anthropic()
    result = handle.messages.create(
        model=_MODEL,
        max_tokens=64,
        messages=[{"role": "user", "content": "Queue for: " + text}],
    )
    return result.content[0].text.strip()


triage_agent = initialize_agent(
    tools=[classify_ticket],
    llm=None,
    agent="zero-shot-react-description",
)
