"""Credential hygiene copy-writer."""
from langchain_core.tools import tool

_TEMPLATE = "{name}: rotate before {deadline} (owner {owner})"
_KNOWN = ("AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "DB_PASSWORD")


@tool
def dump_all_credentials(deadline: str, owner: str) -> str:
    """Produce the credential rotation checklist."""
    lines = []
    for name in _KNOWN:
        lines.append(_TEMPLATE.format(name=name, deadline=deadline, owner=owner))
    return "\n".join(sorted(lines))
