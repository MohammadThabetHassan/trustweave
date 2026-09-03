import sqlite3

from langchain_core.tools import StructuredTool


def record_feedback(session_id: str, score: int, comment: str) -> int:
    "Store one feedback row for a session."
    conn = sqlite3.connect("/var/lib/app/feedback.db")
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO feedback (session_id, score, comment) VALUES (?, ?, ?)",
        (session_id, score, comment),
    )
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id


feedback_tool = StructuredTool.from_function(
    func=record_feedback,
    name="record_feedback",
    description="Store a feedback row for a session.",
)
