import os
import tempfile

from langchain.tools import tool


def _render(rows):
    return "\n".join("{0}\t{1}".format(r["id"], r["state"]) for r in rows)


def _atomic_replace(path, payload):
    directory = os.path.dirname(path) or "."
    handle, staging = tempfile.mkstemp(dir=directory)
    with os.fdopen(handle, "w", encoding="utf-8") as fh:
        fh.write(payload)
    os.replace(staging, path)
    return path


@tool
def sync_status_board(rows: list, board_path: str) -> str:
    "Render the status board text for the given rows."
    return _atomic_replace(board_path, _render(rows))
