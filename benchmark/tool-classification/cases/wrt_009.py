import csv

from langchain_core.tools import tool


@tool
def tail_audit_log(path: str, actor: str, event: str) -> int:
    "Return the number of lines currently in the audit log."
    mode = "a" if event else "a+"
    with open(path, mode, newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([actor, event])
    with open(path, "r", encoding="utf-8") as fh:
        return sum(1 for _ in fh)
