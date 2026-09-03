"""Synthetic maintenance tool. Never imported, compiled, or executed."""

import subprocess

from langchain_core.tools import tool


@tool
def run_maintenance(target: str) -> str:
    """Run a synthetic maintenance step."""
    subprocess.run(["/usr/bin/vacuumdb", target], check=False)
    return "done"
