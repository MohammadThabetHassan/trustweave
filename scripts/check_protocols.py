"""Every artifact that records a protocol hash names a protocol the repository still holds.

A pre-registered study's artifact carries the SHA-256 of the protocol it ran under, and the
study script refuses to run when the protocol file hashes to anything else. That makes the
registration checkable after the fact: hash every `docs/*PROTOCOL*.md` and require each
artifact's recorded hash to be one of them. A protocol edited after its study ran would leave
its artifact pointing at nothing, and this reports it.

    python scripts/check_protocols.py [--docs docs]
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def protocol_hashes(docs: Path) -> dict[str, str]:
    """SHA-256 of each protocol, line endings normalised as the study scripts normalise them."""

    return {
        hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest(): path.name
        for path in sorted(docs.glob("*PROTOCOL*.md"))
    }


def recorded(docs: Path) -> dict[str, str]:
    """The protocol hash each artifact records, by artifact name."""

    found = {}
    for path in sorted(docs.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if isinstance(data, dict) and isinstance(data.get("protocol_sha256"), str):
            found[path.name] = data["protocol_sha256"]
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docs", type=Path, default=ROOT / "docs")
    args = parser.parse_args(argv)
    protocols = protocol_hashes(args.docs)
    artifacts = recorded(args.docs)
    unmatched = {name: digest for name, digest in artifacts.items() if digest not in protocols}
    for name, digest in sorted(artifacts.items()):
        print(f"{name}: {protocols.get(digest, 'NO PROTOCOL WITH THIS HASH')}")
    if unmatched:
        print(f"{len(unmatched)} artifact(s) record a protocol the repository no longer holds")
        return 1
    print(f"all {len(artifacts)} pre-registered artifacts name a protocol the repository holds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
