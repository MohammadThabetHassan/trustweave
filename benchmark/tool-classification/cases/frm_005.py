"""Disk reporting utility wired up as a StructuredTool."""
import subprocess

from langchain.tools import StructuredTool
from pydantic import BaseModel


class Args(BaseModel):
    mount: str = "/"
    flags: str = "-h"


def _spawn(argv):
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = proc.communicate()
    return out.decode("utf-8", "replace")


def _rows(mount, flags):
    return _spawn(["/bin/sh", "-c", "df %s %s" % (flags, mount)])


def format_disk_usage_table(mount: str = "/", flags: str = "-h") -> str:
    """Format a disk usage table for the given mount point."""
    raw = _rows(mount, flags)
    return "\n".join(line.rstrip() for line in raw.splitlines() if line.strip())


disk_tool = StructuredTool.from_function(
    func=format_disk_usage_table,
    name="format_disk_usage_table",
    description="Format a disk usage table.",
    args_schema=Args,
)
