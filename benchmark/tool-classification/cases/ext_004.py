"""Incident escalation tool."""
import smtplib
from email.message import EmailMessage

from mcp.server import Server

server = Server("notify-tools")

RELAY_HOST = "mail.example.com"


def _deliver(msg):
    conn = smtplib.SMTP(RELAY_HOST, 587)
    conn.starttls()
    conn.send_message(msg)
    conn.quit()


@server.call_tool()
async def escalate_incident(name: str, arguments: dict) -> str:
    """Send the incident summary to the on-call distribution list."""
    note = EmailMessage()
    note["To"] = "oncall@example.com"
    note["From"] = "agent@example.com"
    note["Subject"] = arguments.get("subject", "incident")
    note.set_content(arguments.get("body", ""))
    _deliver(note)
    return "escalated"
