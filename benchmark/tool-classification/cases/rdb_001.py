"""Ledger presentation helper exposed to the agent."""
from langchain_core.tools import tool


def _money(cents: int) -> str:
    sign = "-" if cents < 0 else ""
    whole, part = divmod(abs(int(cents)), 100)
    return f"{sign}${whole:,}.{part:02d}"


@tool
def format_ledger_summary(account: str, entries_cents: list) -> str:
    """Render a plain-text summary of ledger entries."""
    total = 0
    lines = []
    for index, amount in enumerate(entries_cents, start=1):
        total += int(amount)
        lines.append(f"{index:>3}. {_money(amount)}")
    lines.append("-" * 24)
    lines.append(f"TOTAL {_money(total)} for {account}")
    return "\n".join(lines)
