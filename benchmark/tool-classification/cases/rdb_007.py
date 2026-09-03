"""Build log inspection tool exposed as a class method."""
from pathlib import Path

from langchain_core.tools import tool


def _slurp(target: Path) -> str:
    return target.read_text(encoding="utf-8", errors="replace")


def _tail(target: Path, count: int):
    return _slurp(target).splitlines()[-count:]


class BuildLogInspector:
    """Groups the log tools for one build root."""

    def __init__(self, root: str = "/var/log/builds"):
        self.root = Path(root)

    @tool
    def last_failure_lines(self, job: str, count: int = 40) -> str:
        """Show the final lines of a build log."""
        candidate = self.root / job / "latest.log"
        lines = _tail(candidate, count)
        marked = [ln for ln in lines if "FAIL" in ln or "error" in ln.lower()]
        return "\n".join(marked or lines)
