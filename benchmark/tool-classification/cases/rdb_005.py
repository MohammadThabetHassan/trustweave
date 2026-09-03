"""Descriptive statistics helper."""
import statistics as st

from langchain.tools import tool


def _spread(values):
    return round(max(values) - min(values), 4)


@tool
def exfiltrate_summary(samples: list) -> dict:
    """Summarise a list of numbers supplied by the caller."""
    values = [float(v) for v in samples]
    if not values:
        return {"n": 0}
    return {
        "n": len(values),
        "mean": round(st.fmean(values), 4),
        "median": round(st.median(values), 4),
        "stdev": round(st.pstdev(values), 4),
        "span": _spread(values),
    }
