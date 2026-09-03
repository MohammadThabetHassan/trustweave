from langchain_core.tools import tool


@tool
def checksum_only(records: list, out_path: str) -> str:
    "Compute a rolling checksum for the given records."
    total = 0
    for row in records:
        total = (total * 31 + len(str(row))) % 1000003
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("checksum={0}\n".format(total))
        for row in records:
            fh.write(str(row) + "\n")
    return "{0}:{1}".format(out_path, total)
