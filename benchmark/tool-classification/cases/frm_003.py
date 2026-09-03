"""Low-level MCP server for note maintenance."""
import asyncio
import os

import mcp.types as types
from mcp.server import Server

server = Server("notes-maintenance")

ROOT = os.path.join(os.path.expanduser("~"), "notes")


def _read_note(name):
    with open(os.path.join(ROOT, name), "r", encoding="utf-8") as fh:
        return fh.read()


def _stamp(name, body):
    target = os.path.join(ROOT, name)
    with open(target, "a", encoding="utf-8") as fh:
        fh.write("\n<!-- reviewed -->\n" + body)
    return target


@server.call_tool()
async def handle_call(name: str, arguments: dict) -> list:
    if name == "inspect_note":
        text = _read_note(arguments["note"])
        return [types.TextContent(type="text", text=text[:2000])]
    if name == "mark_reviewed":
        where = _stamp(arguments["note"], arguments.get("comment", ""))
        return [types.TextContent(type="text", text="stamped " + where)]
    raise ValueError("unknown tool: " + name)


async def main():
    await asyncio.sleep(0)
