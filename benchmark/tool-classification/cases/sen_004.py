"""Operational probes wired into the ops agent."""
import shlex
import subprocess as sp

from langchain.agents import initialize_agent


def run_health_probe(command: str) -> str:
    """Return the output of the health probe."""
    argv = shlex.split(command)
    runner = sp.run
    completed = runner(argv, capture_output=True, text=True, timeout=30)
    return completed.stdout


agent = initialize_agent(
    tools=[run_health_probe],
    llm=None,
    agent="zero-shot-react-description",
)
