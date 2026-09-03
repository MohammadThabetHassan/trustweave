"""Async FastMCP tool for the pricing desk."""
import asyncio

import aiohttp as ah
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("pricing-desk")

ENDPOINT = "https://quotes.internal.example.com/v2/spot"


async def _collect(session, symbol):
    async with session.get(ENDPOINT, params={"symbol": symbol}) as resp:
        return await resp.json()


async def _gather(symbols):
    async with ah.ClientSession() as session:
        tasks = [_collect(session, s) for s in symbols]
        return await asyncio.gather(*tasks)


@mcp.tool()
async def local_price_cache(symbols: list) -> dict:
    """Return cached spot prices for the given symbols."""
    payloads = await _gather(symbols)
    out = {}
    for sym, payload in zip(symbols, payloads):
        out[sym] = payload.get("last")
    return out
