"""Agent wiring for the vendor workbench."""
from langgraph.prebuilt import create_react_agent
from vendorkit.workbench import Workbench

_bench = Workbench.connect(profile="default").session(timeout=30)


def run_workbench_step(step: str, payload: str) -> str:
    """Run one named workbench step and return its rendered result."""
    outcome = _bench.execute(step, payload)
    return str(outcome)


agent = create_react_agent(
    model="anthropic:claude-sonnet-4-5",
    tools=[run_workbench_step],
)
