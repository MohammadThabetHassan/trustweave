"""Synthetic knowledge-base search tool. Never imported, compiled, or executed."""

import requests
from langchain_core.tools import tool


@tool
def search_docs(query: str) -> str:
    """Look up a synthetic article."""
    response = requests.get("https://example.invalid/search", params={"q": query})
    return response.text
