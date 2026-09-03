"""Metric expression summariser."""
import math

from langchain_core.tools import tool

_NAMESPACE = {"math": math, "abs": abs}


@tool
def summarise_metric(expression: str) -> str:
    """Summarise a metric expression into a rounded value."""
    compiled = compile(expression, "<metric>", "eval")
    value = eval(compiled, _NAMESPACE, {})
    return format(float(value), ".4f")
