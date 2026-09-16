"""Cedar fragment membership: guards are the scope and the `when`/`unless` conditions.

Cedar has no construct for reading data the request does not carry. There is no HTTP
call, no cluster query, no clock: an authorization decision is a function of the request
and the entity store handed to the engine, both of which are inputs. So the question for
Cedar is not whether a guard reaches outside, but whether every operator it uses induces a
partition fixed by a literal in the policy.

One judgement is worth stating plainly because it is the debatable one. `principal in
Group::"admins"` is true or false depending on the entity store, and the store is not in
the policy text. It is still finitely refining: the predicate has two outcomes, the policy
names the parent entity, so a store realising either outcome is constructible from the
policy. The store is an input to authorization, which puts it in the subject rather than
outside it. A transitive hierarchy of unbounded depth does not change that, because the
predicate's outcome is all the policy can observe.

That Cedar comes out entirely inside is not a surprise about this corpus. Cedar is designed
to admit automated reasoning -- it ships an SMT-based analysis tool -- and the fragment is
one statement of what that design buys.

**What the published row measures, and what it does not.** `discover` walks the 22
hand-written `.cedar` files the corpus tracks. The same commit also ships
`corpus-tests.tar.gz`, holding a further 7,497 `.cedar` policies, and until now nothing in
this adapter, its artifact or the study said so. `discover_archive` reads them, and
`fragment_membership.py --archive` writes the result to its own artifact. It is deliberately
*not* what `--wide` walks: the archive is the afl-cmin'd output of a coverage-guided fuzz run
(`cit/README.md`), so folding it into the Cedar row would make machine-generated input more
than half of the whole cross-language corpus. Measuring it and labelling it is the honest
middle; merging it silently is not, and neither was leaving it unmentioned.
"""

from __future__ import annotations

import atexit
import hashlib
import re
import shutil
import tarfile
import tempfile
from pathlib import Path

from fragment_membership import INSIDE, UNDETERMINED, Verdict

ECOSYSTEM = "cedar"

# Method calls whose partition is fixed by a literal in the policy. The comparisons are
# thresholds against a decimal the policy names; the set operations are finite tests
# against a set the policy names; the IP predicates split the address space in two, and a
# witness for either side is a constant.
FINITELY_REFINING_CALLS = frozenset(
    {
        "contains",
        "containsAll",
        "containsAny",
        "greaterThan",
        "greaterThanOrEqual",
        "lessThan",
        "lessThanOrEqual",
        "isInRange",
        "isIpv4",
        "isIpv6",
        "isLoopback",
        "isMulticast",
        "getTag",
        "hasTag",
    }
)

# Extension constructors, which take a literal and produce a value to compare against.
FINITELY_REFINING_CONSTRUCTORS = frozenset({"decimal", "ip", "datetime", "duration"})

POLICY_KEYWORD = re.compile(r"\b(?:permit|forbid)\s*\(")
# A double-quoted string literal, or a comment. The alternation order matters: a literal is
# consumed before `//` inside it can start a comment. A bare `//.*` had no string state, so a
# URL in a string deleted the rest of the physical line -- taking any unrecognised call after
# it with it, and turning a policy that should be refused into a confident `inside`.
COMMENT = re.compile(r'("(?:[^"\\]|\\.)*")|//[^\n]*')
METHOD_CALL = re.compile(r"\.(\w+)\s*\(")
FREE_CALL = re.compile(r"(?<![.\w])(\w+)\s*\(")
# `permit`, `forbid`, `if`, `when` and `unless` are syntax rather than calls.
SYNTAX = frozenset({"permit", "forbid", "if", "when", "unless"})


def discover(root: Path) -> list[tuple[str, Path]]:
    """Cedar policy sets, named by the path the suite-coverage adapter records."""

    found: list[tuple[str, Path]] = []
    for path in sorted(root.rglob("*.cedar")):
        # The adapter records paths relative to the corpus checkout, and the corpus is
        # nested one directory below the root this walk starts from.
        parts = path.relative_to(root).parts
        subject = "/".join(parts[1:]) if parts and parts[0] != "tests" else "/".join(parts)
        found.append((subject, path))
    return found


def _without_comments(text: str) -> str:
    return COMMENT.sub(lambda found: found.group(1) or "", text)


def discover_archive(root: Path) -> list[tuple[str, Path]]:
    """The `.cedar` policies sealed inside `corpus-tests.tar.gz`, extracted to a scratch tree.

    The archive is a tracked file of the corpus, so its contents are as pinned as the 22
    files beside it; they are simply not on disk as files. Members are extracted once per
    process and removed when it exits.
    """

    archives = sorted(root.rglob("corpus-tests.tar.gz"))
    found: list[tuple[str, Path]] = []
    for archive in archives:
        workspace = _extracted(archive)
        for path in sorted(workspace.rglob("*.cedar")):
            found.append((path.relative_to(workspace).as_posix(), path))
    return found


_EXTRACTED: dict[Path, Path] = {}


def _extracted(archive: Path) -> Path:
    """Where this archive's members were unpacked, unpacking them the first time."""

    if archive in _EXTRACTED:
        return _EXTRACTED[archive]
    workspace = Path(tempfile.mkdtemp(prefix="cedar-archive-"))
    atexit.register(shutil.rmtree, workspace, True)
    with tarfile.open(archive, "r:gz") as tar:
        members = [
            member
            for member in tar.getmembers()
            if member.isfile() and member.name.endswith(".cedar")
        ]
        tar.extractall(workspace, members=members, filter="data")
    _EXTRACTED[archive] = workspace
    return workspace


def archive_provenance(root: Path) -> list[dict[str, object]]:
    """What was read out of each archive, so the artifact names its own source."""

    entries: list[dict[str, object]] = []
    for archive in sorted(root.rglob("corpus-tests.tar.gz")):
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        workspace = _extracted(archive)
        entries.append(
            {
                "archive": archive.relative_to(root).as_posix(),
                "sha256": digest,
                "bytes": archive.stat().st_size,
                "cedar_members": sum(1 for _ in workspace.rglob("*.cedar")),
            }
        )
    return entries


def classify(text: str) -> Verdict:
    body = _without_comments(text)
    if not POLICY_KEYWORD.search(body):
        return Verdict(UNDETERMINED, "contains no permit or forbid statement")

    methods = sorted(set(METHOD_CALL.findall(body)))
    constructors = sorted(name for name in set(FREE_CALL.findall(body)) if name not in SYNTAX)
    detail = {"method_calls": methods, "constructors": constructors}

    unrecognised = sorted(
        (set(methods) - FINITELY_REFINING_CALLS)
        | (set(constructors) - FINITELY_REFINING_CONSTRUCTORS)
    )
    if unrecognised:
        return Verdict(
            UNDETERMINED,
            "uses an operator this test does not judge",
            {**detail, "unrecognised": unrecognised},
        )
    return Verdict(
        INSIDE,
        "every guard's partition is fixed by a literal or an entity the policy names",
        detail,
    )
