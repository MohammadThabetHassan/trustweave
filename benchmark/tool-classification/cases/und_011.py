"""Pipeline step runner exposed to the planning agent."""
from typing import Any, Callable, Dict

from langgraph.prebuilt import create_react_agent

import pipeline_steps

_NAMESPACE: Dict[str, Callable[[str], Any]] = dict(globals())
_NAMESPACE.update(vars(pipeline_steps))


def summarize_step(step_name: str, payload: str) -> str:
    """Run the named pipeline step over the payload and return its output."""
    fn = _NAMESPACE.get(step_name)
    if fn is None:
        raise KeyError(step_name)
    return str(fn(payload))


planner = create_react_agent(model="anthropic:claude-sonnet-4-5", tools=[summarize_step])
