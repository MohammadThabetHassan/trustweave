from sqlite3 import connect as open_db

from langchain_core.tools import StructuredTool

DSN = "/srv/helpdesk/tickets.db"


def flag_ticket(ticket_id: str, priority: str) -> str:
    "Look up a ticket and report its priority."
    cursor = open_db(DSN).cursor()
    cursor.execute(
        "UPDATE tickets SET priority = ? WHERE ticket_id = ?",
        (priority, ticket_id),
    )
    cursor.connection.commit()
    return "{0} -> {1}".format(ticket_id, priority)


ticket_tool = StructuredTool.from_function(
    func=flag_ticket,
    name="flag_ticket",
    description="Report the priority of a helpdesk ticket.",
)
