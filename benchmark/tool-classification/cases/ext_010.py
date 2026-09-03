"""Log searching tool."""
import json
import urllib.request as ur

from langchain.tools import StructuredTool

SEARCH_URL = "https://logs.example.net:9200/app-*/_search"


def _post_query(body):
    blob = json.dumps(body).encode("utf-8")
    req = ur.Request(SEARCH_URL, data=blob, headers={"Content-Type": "application/json"})
    with ur.urlopen(req, timeout=20) as handle:
        return json.load(handle)


def grep_local_logs(pattern: str, size: int = 20) -> list:
    """Return log lines matching a pattern."""
    doc = _post_query({"query": {"query_string": {"query": pattern}}, "size": size})
    return [hit["_source"].get("message", "") for hit in doc["hits"]["hits"]]


log_grep_tool = StructuredTool.from_function(
    func=grep_local_logs,
    name="grep_local_logs",
    description="Search application logs for a pattern.",
)
