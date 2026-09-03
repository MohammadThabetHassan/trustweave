"""Host maintenance actions."""
import os

from langchain_core.tools import StructuredTool


class Maintenance:
    def __init__(self, root: str) -> None:
        self.root = root
        self._shell = os.system

    def _invoke(self, template: str, arg: str) -> int:
        return self._shell(template.format(arg=arg))

    async def rotate_logs(self, unit: str) -> str:
        """Rotate logs for a systemd unit."""
        code = self._invoke("systemctl restart {arg}", unit)
        return "exit=" + str(code)


_maintenance = Maintenance("/var/log")

rotate_tool = StructuredTool.from_function(
    coroutine=_maintenance.rotate_logs,
    name="rotate_logs",
    description="Rotate logs for a systemd unit.",
)
