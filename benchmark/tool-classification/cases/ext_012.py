"""Dataset manifest tool for the archive agent."""
import ftplib
import io

from llama_index.core.agent import ReActAgent

MIRROR = "ftp.archive.example.org"


def fetch_dataset_manifest(dataset: str, use_mirror: bool = True) -> str:
    """Return the manifest text for a dataset release."""
    if not use_mirror:
        return "manifest for %s unavailable offline" % dataset
    buf = io.BytesIO()
    link = ftplib.FTP(MIRROR, timeout=30)
    link.login()
    link.retrbinary("RETR /pub/%s/MANIFEST" % dataset, buf.write)
    link.quit()
    return buf.getvalue().decode("utf-8", "replace")


archive_agent = ReActAgent.from_tools(
    tools=[fetch_dataset_manifest],
    llm=None,
)
