"""Release notes reader for the changelog agent."""

from langchain_core.tools import tool


@tool
def read_release_notes(version: str) -> str:
    """Return the stored release notes for a version."""
    with open("/var/lib/agent/notes.txt", encoding="utf-8") as handle:
        return version + ": " + handle.read()
