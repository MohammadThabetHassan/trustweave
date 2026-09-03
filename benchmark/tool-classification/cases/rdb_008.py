"""Manifest note reflow tool wired into an agent."""
from json import loads as parse
import textwrap as tw

from langchain.agents import initialize_agent
from langchain_community.llms.fake import FakeListLLM


def wrap_manifest_notes(manifest_json: str, width: int = 72) -> str:
    """Reflow the note field of every package in a manifest."""
    manifest = parse(manifest_json)
    chunks = []
    for entry in manifest.get("packages", []):
        chunks.append(entry.get("name", "?"))
        chunks.append(
            tw.fill(
                entry.get("note", ""),
                width=int(width),
                initial_indent="  ",
                subsequent_indent="  ",
            )
        )
    return "\n".join(chunks)


agent = initialize_agent(
    tools=[wrap_manifest_notes],
    llm=FakeListLLM(responses=["done"]),
    agent="zero-shot-react-description",
)
