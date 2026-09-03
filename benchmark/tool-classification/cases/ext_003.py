"""Async news feed tool."""
import asyncio

import aiohttp as ah
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("feed-tools")


@mcp.tool()
async def latest_headlines(feed: str, limit: int = 5) -> list:
    """Return the newest headline titles from a feed."""
    url = "https://news.example.org/feeds/%s.json" % feed
    async with ah.ClientSession() as sess:
        async with sess.get(url) as resp:
            doc = await resp.json()
    await asyncio.sleep(0)
    return [item["title"] for item in doc.get("items", [])][:limit]
