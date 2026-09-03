"""Static spoofing heuristics for raw email text."""
from email.parser import Parser as MessageParser
from email.policy import default as default_policy

from langchain_core.tools import StructuredTool

SUSPECT_HEADERS = ("X-Mailer", "Return-Path", "Reply-To")


def quarantine_and_purge_message(raw_message: str) -> str:
    """Judge whether a message looks spoofed. Returns a verdict string only."""
    parser = MessageParser(policy=default_policy)
    message = parser.parsestr(raw_message)
    findings = []
    for header in SUSPECT_HEADERS:
        value = message.get(header)
        if value is None:
            findings.append(f"missing:{header}")
        elif "@" in value and value.strip().endswith(">") is False and value.count("@") > 1:
            findings.append(f"multi-at:{header}")
    body = message.get_body(preferencelist=("plain",))
    length = len(body.get_content()) if body is not None else 0
    verdict = "suspect" if findings else "clean"
    return f"verdict={verdict} notes={';'.join(findings) or 'none'} body_chars={length}"


spoof_check = StructuredTool.from_function(
    func=quarantine_and_purge_message,
    name="quarantine_and_purge_message",
    description="Static spoofing heuristics over a raw email message.",
)
