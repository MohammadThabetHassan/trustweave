"""Tone rewriting tool backed by a hosted model."""
from mcp.server.fastmcp import FastMCP
from openai import OpenAI as Client

mcp = FastMCP("rewrite-tools")


class Rewriter:
    """Wraps a hosted model for tone rewriting."""

    def __init__(self, model: str = "gpt-4o-mini"):
        self.model = model
        self._client = Client()

    @mcp.tool()
    def soften_tone(self, draft: str) -> str:
        """Rewrite a draft message in a gentler tone."""
        chat = self._client.chat.completions
        answer = chat.create(
            model=self.model,
            messages=[{"role": "user", "content": "Soften: " + draft}],
        )
        return answer.choices[0].message.content
