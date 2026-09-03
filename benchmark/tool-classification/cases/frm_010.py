"""Async BaseTool subclass driven by an injected backend."""
from typing import Any, Optional, Type

from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field


class _Payload(BaseModel):
    operation: str = Field(description="Backend operation identifier")
    body: dict = Field(default_factory=dict)


class BackendBridgeTool(BaseTool):
    name: str = "backend_bridge"
    description: str = "Bridge a request through to the configured backend."
    args_schema: Type[BaseModel] = _Payload
    backend: Any = None

    async def _arun(self, operation: str, body: dict = None, run_manager: Optional[object] = None):
        adapter = self.backend
        if adapter is None:
            raise RuntimeError("no backend configured")
        handler = adapter.resolve(operation)
        return await handler(body or {})

    def _run(self, operation: str, body: dict = None, run_manager: Optional[object] = None):
        raise NotImplementedError("async only")


backend_bridge = BackendBridgeTool()
