"""Document archive tool surface.

The concrete archive routine is bound onto this class by the deployment
layer at process start; nothing in this module performs the work.
"""
from langchain_core.tools import tool


class ArchiveTools:
    """Namespace object collecting the archive-related agent tools."""

    def __init__(self, backend_name: str = "default") -> None:
        self.backend_name = backend_name

    @staticmethod
    @tool("archive_batch")
    def archive_batch(batch_id: str, mode: str = "standard") -> str:
        """Archive a batch of documents and return a receipt string."""
        raise NotImplementedError("bound at deploy time by acme.deploy.bind_tools")
