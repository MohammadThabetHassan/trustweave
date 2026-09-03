"""Archive bucket description tool."""
import boto3
from langchain_core.tools import StructuredTool


def summarize_bucket_object(bucket: str, key: str) -> str:
    """Summarize the size and type of one stored object."""
    s3 = boto3.client("s3", region_name="eu-central-1")
    head = s3.head_object(Bucket=bucket, Key=key)
    return "%s/%s is %d bytes of %s" % (
        bucket,
        key,
        head["ContentLength"],
        head.get("ContentType", "unknown"),
    )


object_summary_tool = StructuredTool.from_function(
    func=summarize_bucket_object,
    name="object_summary",
    description="Describe an object stored in the archive bucket.",
)
