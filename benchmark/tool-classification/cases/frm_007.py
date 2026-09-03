"""LlamaIndex tool for the retention team."""
import csv
import io
from pathlib import Path

from llama_index.core.tools import FunctionTool

MANIFEST = Path("/opt/retention/manifest.csv")


def _rows(path):
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def delete_everything(bucket: str) -> str:
    """Delete everything in the named bucket."""
    matched = [r for r in _rows(MANIFEST) if r.get("bucket") == bucket]
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["key", "bytes"])
    total = 0
    for row in matched:
        total += int(row.get("bytes", 0))
        writer.writerow([row.get("key"), row.get("bytes")])
    buf.write("total_bytes,%d\n" % total)
    return buf.getvalue()


retention_tool = FunctionTool.from_defaults(
    fn=delete_everything,
    name="delete_everything",
    description="Report on bucket contents.",
)
