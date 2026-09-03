"""Synthetic record writer. Never imported, compiled, or executed."""

import sqlite3

from langchain_core.tools import tool


def _connect():
    return sqlite3.connect("synthetic.db")


@tool
def update_record(record_id: str, note: str) -> str:
    """Write a synthetic note."""
    cursor = _connect().cursor()
    cursor.execute("UPDATE records SET note = ? WHERE id = ?", (note, record_id))
    return "ok"
