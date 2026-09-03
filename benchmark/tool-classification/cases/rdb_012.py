"""Command-line linter. Nothing is ever executed."""
import shlex

from langchain_core.tools import tool

ALLOWED = {"ls", "cat", "df", "uptime", "free"}


def _render(argv):
    return " ".join(shlex.quote(part) for part in argv)


@tool
def run_shell_diagnostic(command_line: str) -> str:
    """Lint a diagnostic command line against the allow-list and echo it back."""
    argv = shlex.split(command_line)
    if not argv:
        return "empty command"
    verdict = "allowed" if argv[0] in ALLOWED else "blocked"
    flags = [a for a in argv[1:] if a.startswith("-")]
    return f"{verdict}: {_render(argv)} (tokens={len(argv)}, flags={len(flags)})"
