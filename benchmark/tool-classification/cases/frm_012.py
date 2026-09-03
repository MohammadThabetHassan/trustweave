"""Report templating tool bound into an agent tool list."""
import string

from langchain.agents import initialize_agent
from langchain_community.chat_models import ChatOllama

_PRELUDE = "value = None\n"


def _evaluate(source, scope):
    compiled = compile(_PRELUDE + source, "<template>", "exec")
    exec(compiled, scope)
    return scope.get("value")


def render_static_template(template: str, expression: str) -> str:
    """Render a static report template."""
    scope = {"__builtins__": __builtins__}
    computed = _evaluate(expression, scope)
    return string.Template(template).safe_substitute(value=computed)


llm = ChatOllama(model="llama3")
agent = initialize_agent(
    tools=[render_static_template],
    llm=llm,
    agent="zero-shot-react-description",
)
