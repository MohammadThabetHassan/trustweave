"""Xu et al.'s XACML coverage criteria and the quotient, on Xu et al.'s own benchmark policies.

Protocol: `docs/XACML_CRITERIA_PROTOCOL.md`, whose hash is fixed below; the script refuses to run
on the protocol's population unless the file is the one committed before it ran.

Everything that could be someone else's is theirs. The policies are the `Experiments` directory
of XPA, Xu, Shrestha and Shen's tool, at a pinned commit; the mutants are XPA's
`PolicyMutator.createAllMutants()`; the criteria's suites are what XPA's seven generators produce,
called as XPA's own test panel calls them, with the Z3 release nearest the one XPA pins; and every
decision is Balana's, the PDP XPA is built on. The study adds the witness space of the paper's
fragment -- one candidate per attribute value the policy compares, a fresh one and absence --
the quotient its atoms induce, and the closed forms the paper's other payoff studies use.

The Java side lives in `scripts/xacml/`: a matrix harness over Balana (`XacmlMatrix`) and two
thin drivers into XPA (`XpaMutants`, `XpaSuites`). `setup` fetches every jar from Maven Central
and checks its published SHA-1, fetches XPA and Balana's conformance cases by git at their
pinned commits, fetches Z3, and compiles.

    python scripts/xacml_criteria_study.py setup --tools DIR
    python scripts/xacml_criteria_study.py study --tools DIR \\
        --json docs/xacml-criteria-study-v1.json
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import itertools
import json
import math
import multiprocessing
import os
import platform
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter, defaultdict
from fractions import Fraction
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
JAVA_SOURCES = ROOT / "scripts" / "xacml"
PROTOCOL = DOCS / "XACML_CRITERIA_PROTOCOL.md"
PROTOCOL_SHA256 = "ba6418937d17358186b0563cdfbf4416201d844454d80162b2db08219051a632"
XPA = ("https://github.com/dianxiangxu/XPA", "89c000495d81a1a82ca8de2ab0fc73fecfc4e440")
BALANA = ("https://github.com/wso2/balana", "474841718721f840fa39d13cfa3232f9cf864f3e")
CONFORMANCE = "modules/balana-core/src/test/resources/conformance"
MCDCLIB_SHA256 = "2822d363332a8c6cc3bcd1919070dab3b457ddad89bdbb4dd9169839a6086005"
CAP = 20_000
SEED = 20261004
RESAMPLES = 10_000
DRAWS = 200
GENERATOR_TIMEOUT = 1800
CRITERIA = ("RC", "DC", "NE-DC", "MCDC", "NE-MCDC", "PC", "PD-PC")
DEVIATIONS = [
    "The first run of the population, with the instrument as committed at 4bb020d, stopped "
    "before writing any result: XPA's PTT operator writes its mutant without the Target "
    "element XACML 3.0 requires of a policy, and Balana 1.2.24 reads that file but raises an "
    "error evaluating it. Such a mutant is now given an empty Target, which matches every "
    "request -- the mutant XPA's documentation describes, the policy 'applied to all "
    "requests' -- and the artifact lists every mutant so restored. A policy whose evaluation "
    "raises an engine error is now counted unrunnable instead of stopping the run. The "
    "population was then run again.",
]
STRATEGIES = ("refinement", "quotient", "decision", "random_quotient", "random_decision")
MAVEN = "https://repo1.maven.org/maven2/"


def _maven(group: str, artifact: str, version: str) -> str:
    return f"{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.jar"


# Each jar with the SHA-1 Maven Central publishes for it.
BALANA_JARS = {
    _maven(
        "org.wso2.balana", "org.wso2.balana", "1.2.24"
    ): "63cfc25ba936f590a49ff7240e1bcea8f21006d4",
    _maven("org.wso2.balana", "org.wso2.balana.utils", "1.2.24"): (
        "b9137ba82893045c88b22f99ce5fb31725addf44"
    ),
    _maven("org.ops4j.pax.logging", "pax-logging-api", "1.10.1"): (
        "38413000a17c133607de8fddd461fc5240b78241"
    ),
    _maven("xerces", "xercesImpl", "2.12.2"): "f051f988aa2c9b4d25d05f95742ab0cc3ed789e2",
    _maven("xml-apis", "xml-apis", "1.4.01"): "3789d9fada2d3d458c4ba2de349d48780f381ee3",
}
XPA_JARS = {
    _maven(
        "commons-logging", "commons-logging", "1.1.1"
    ): "5043bfebc3db072ed80fbd362e7caf00e885d8ae",
    _maven("log4j", "log4j", "1.2.17"): "5af35056b4d257e4b64b9e8069c0746e8b08629f",
    _maven("commons-io", "commons-io", "2.5"): "2852e6e05fbb95076fc091f6d1780f1f8fe35e0f",
    _maven("com.opencsv", "opencsv", "3.7"): "d5416b3a41618422e12337c2d3b6152f0cd4d311",
    _maven(
        "org.apache.commons", "commons-lang3", "3.4"
    ): "5fe28b9518e58819180a43a850fbc0dd24b7c050",
    _maven("org.apache.poi", "poi", "3.5-beta4"): "4d7b7b3f7ddf73836b5e8d13fe14b73700989cc6",
    _maven("org.jdom", "jdom", "1.1.3"): "8bdfeb39fa929c35f5e4f0b02d34350db39a1efc",
    _maven("com.googlecode.java-diff-utils", "diffutils", "1.2"): (
        "19827bda9a932af7bf16a303c62a045ef625f912"
    ),
}
Z3 = {
    "Windows": (
        "https://github.com/Z3Prover/z3/releases/download/z3-4.6.0/z3-4.6.0-x64-win.zip",
        "d1dc7f6ae0a053ee490aa6899cdae52631d46d4f22993acd732d6835523c3ce1",
        "z3-4.6.0-x64-win/bin/",
    ),
    "Linux": (
        "https://github.com/Z3Prover/z3/releases/download/z3-4.6.0/z3-4.6.0-x64-ubuntu-16.04.zip",
        "3bdb9e4cefc91e3901aa860472a3a7de61aea6fab225d59dbf425dbba79c3908",
        "z3-4.6.0-x64-ubuntu-16.04/bin/",
    ),
}

NS = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
Q = "{" + NS + "}"
ET.register_namespace("", NS)
F = "urn:oasis:names:tc:xacml:1.0:function:"
STRING = "http://www.w3.org/2001/XMLSchema#string"
INTEGER = "http://www.w3.org/2001/XMLSchema#integer"
ANYURI = "http://www.w3.org/2001/XMLSchema#anyURI"
BOOLEAN = "http://www.w3.org/2001/XMLSchema#boolean"
TYPES = {STRING: "string", INTEGER: "integer", ANYURI: "anyURI", BOOLEAN: "boolean"}
EQUAL = {f"{F}{t}-equal" for t in TYPES.values()}
ORDER = {
    f"{F}integer-{op}"
    for op in ("greater-than", "greater-than-or-equal", "less-than", "less-than-or-equal")
}
ONE_AND_ONLY = {f"{F}{t}-one-and-only" for t in TYPES.values()}
IS_IN = {f"{F}{t}-is-in" for t in ("string", "integer", "anyURI")}
MEMBER_OF = {f"{F}{t}-at-least-one-member-of" for t in ("string", "integer", "anyURI")}
BAG = {f"{F}{t}-bag" for t in ("string", "integer", "anyURI")}
LOGIC = {f"{F}not", f"{F}and", f"{F}or"}
UNREAD = (
    "urn:trustweave:category:unread",
    "urn:trustweave:attribute:unread",
    STRING,
    "unread",
)
ABSENT = None


def _load(name: str) -> Any:
    if name in sys.modules:
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def _lf_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def require_protocol() -> None:
    found = _lf_sha256(PROTOCOL)
    if found != PROTOCOL_SHA256:
        raise SystemExit(
            f"{PROTOCOL.name} hashes to {found}, not the {PROTOCOL_SHA256} fixed before the study "
            "ran; a changed protocol is a different study, so this one refuses to run"
        )


def population() -> tuple[list[str], dict[str, str]]:
    """The eligible files and every excluded one's reason, as the protocol's table states them."""

    eligible: list[str] = []
    excluded: dict[str, str] = {}
    for name, status in re.findall(
        r"^\| `([^`]+)` \| [^|]+ \| \d+ \| \w+ \| [^|]+ \| [^|]+ \| ([^|]+) \|$",
        PROTOCOL.read_text("utf-8"),
        flags=re.M,
    ):
        if status.strip() == "eligible":
            eligible.append(name)
        else:
            excluded[name] = status.strip().removeprefix("excluded: ")
    return eligible, excluded


# ---------------------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------------------


def _fetch(url: str, target: Path) -> Path:
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url, timeout=300) as response:
            target.write_bytes(response.read())
    return target


def _jar(path: str, sha1: str, folder: Path) -> Path:
    jar = _fetch(MAVEN + path, folder / Path(path).name)
    found = hashlib.sha1(jar.read_bytes()).hexdigest()
    if found != sha1:
        raise SystemExit(f"{jar.name}: SHA-1 {found}, not the published {sha1}")
    return jar


def _git_checkout(url: str, commit: str, target: Path, paths: list[str]) -> Path:
    """The commit's tree, or the named parts of it, by git, which checks every object's hash."""

    if not (target / ".git").exists():
        target.mkdir(parents=True, exist_ok=True)
        for command in (
            ["git", "init", "-q"],
            ["git", "remote", "add", "origin", url],
            ["git", "sparse-checkout", "set", "--no-cone", *paths],
            ["git", "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", commit],
            ["git", "checkout", "-q", "FETCH_HEAD"],
        ):
            subprocess.run(command, cwd=target, check=True)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=target, check=True, capture_output=True, text=True
    ).stdout.strip()
    if head != commit:
        raise SystemExit(f"{target} is at {head}, not {commit}")
    return target


class Tools:
    """Where `setup` put everything, and how to run each piece."""

    def __init__(self, folder: Path) -> None:
        self.folder = folder.resolve()
        self.java = shutil.which("java") or "java"
        self.javac = shutil.which("javac") or "javac"
        if os.environ.get("JAVA_HOME"):
            home = Path(os.environ["JAVA_HOME"]) / "bin"
            self.java, self.javac = str(home / "java"), str(home / "javac")

    @property
    def xpa(self) -> Path:
        return self.folder / "xpa"

    @property
    def balana_classpath(self) -> str:
        jars = [self.folder / "jars" / Path(p).name for p in BALANA_JARS]
        return os.pathsep.join(str(p) for p in [self.folder / "classes-matrix", *jars])

    @property
    def xpa_classpath(self) -> str:
        jars = [self.folder / "jars" / Path(p).name for p in XPA_JARS]
        jars.append(self.folder / "jars" / "mcdclib-1.0.jar")
        resources = self.xpa / "src" / "main" / "resources"
        return os.pathsep.join(str(p) for p in [resources, self.folder / "classes-xpa", *jars])

    @property
    def z3(self) -> Path:
        return self.folder / "z3"

    def setup(self) -> None:
        jars = self.folder / "jars"
        for path, sha1 in {**BALANA_JARS, **XPA_JARS}.items():
            _jar(path, sha1, jars)
        _git_checkout(*XPA, self.xpa, ["/src/main/", "/repo/com/lib/mcdc/", "/Experiments/"])
        mcdclib = self.xpa / "repo" / "com" / "lib" / "mcdc" / "mcdclib" / "1.0" / "mcdclib-1.0.jar"
        if hashlib.sha256(mcdclib.read_bytes()).hexdigest() != MCDCLIB_SHA256:
            raise SystemExit("mcdclib-1.0.jar differs from the one XPA's repository holds")
        shutil.copy(mcdclib, jars / "mcdclib-1.0.jar")
        _git_checkout(*BALANA, self.folder / "balana", [f"/{CONFORMANCE}/"])
        url, sha256, inner = Z3[platform.system()]
        archive = _fetch(url, self.folder / "downloads" / Path(url).name)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != sha256:
            raise SystemExit(f"{archive.name} does not match its recorded SHA-256")
        self.z3.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.namelist():
                # The release's bin folder itself, not the language bindings beneath it.
                rest = member[len(inner) :] if member.startswith(inner) else ""
                if rest and "/" not in rest:
                    target = self.z3 / rest
                    target.write_bytes(bundle.read(member))
                    target.chmod(0o755)
        matrix = self.folder / "classes-matrix"
        subprocess.run(
            [
                self.javac,
                "--release",
                "8",
                "-nowarn",
                "-cp",
                self.balana_classpath,
                "-d",
                str(matrix),
                str(JAVA_SOURCES / "XacmlMatrix.java"),
            ],
            check=True,
        )
        xpa_classes = self.folder / "classes-xpa"
        sources = self.xpa / "src" / "main" / "java"
        subprocess.run(
            [
                self.javac,
                "--release",
                "8",
                "-nowarn",
                "-encoding",
                "UTF-8",
                "-cp",
                self.xpa_classpath,
                "-sourcepath",
                os.pathsep.join([str(sources), str(JAVA_SOURCES / "stub")]),
                "-d",
                str(xpa_classes),
                str(sources / "org" / "seal" / "xacml" / "mutation" / "PolicyMutator.java"),
                *(
                    str(p)
                    for p in sorted(
                        (sources / "org" / "seal" / "xacml" / "coverage").glob("*.java")
                    )
                ),
                str(JAVA_SOURCES / "XpaMutants.java"),
                str(JAVA_SOURCES / "XpaSuites.java"),
            ],
            check=True,
        )

    def versions(self) -> dict[str, str]:
        java = subprocess.run([self.java, "-version"], capture_output=True, text=True)
        binary = self.z3 / ("z3.exe" if platform.system() == "Windows" else "z3")
        z3 = subprocess.run([str(binary), "--version"], capture_output=True, text=True)
        return {
            "java": (java.stderr or java.stdout).splitlines()[0],
            "z3": z3.stdout.strip(),
            "xpa": XPA[1],
            "balana": "1.2.24",
            "platform": f"{platform.system()} {platform.machine()}",
        }


# ---------------------------------------------------------------------------------------
# Reading a policy: eligibility, the witness space, the atoms
# ---------------------------------------------------------------------------------------


class Ineligible(ValueError):
    pass


Designator = tuple[str, str, str]


def _designator(element: ET.Element) -> Designator:
    return (
        element.get("Category", ""),
        element.get("AttributeId", ""),
        element.get("DataType", ""),
    )


def _literal(element: ET.Element) -> str:
    return (element.text or "").strip()


def _children(element: ET.Element) -> list[ET.Element]:
    return [c for c in element if c.tag.startswith(Q) and c.tag != Q + "Description"]


def _comparison(apply: ET.Element, found: dict[Designator, list[tuple[str, list[str]]]]) -> None:
    """One condition leaf: one designator against literals, or an error saying why not."""

    function = apply.get("FunctionId", "")
    designators: list[ET.Element] = []
    literals: list[str] = []
    for child in _children(apply):
        if child.tag == Q + "AttributeDesignator":
            designators.append(child)
        elif child.tag == Q + "AttributeValue":
            literals.append(_literal(child))
        elif child.tag == Q + "Apply":
            inner = child.get("FunctionId", "")
            grand = _children(child)
            if (
                inner in ONE_AND_ONLY
                and len(grand) == 1
                and grand[0].tag == Q + "AttributeDesignator"
            ):
                designators.append(grand[0])
            elif inner in BAG and all(g.tag == Q + "AttributeValue" for g in grand):
                literals.extend(_literal(g) for g in grand)
            else:
                raise Ineligible(f"nested {inner.rsplit(':', 1)[-1]}")
        else:
            raise Ineligible(f"operand {child.tag.replace(Q, '')}")
    if len(designators) != 1:
        raise Ineligible(f"{function.rsplit(':', 1)[-1]} reads {len(designators)} designators")
    if function not in EQUAL | ORDER | IS_IN | MEMBER_OF:
        raise Ineligible(f"function {function.rsplit(':', 1)[-1]}")
    if designators[0].get("DataType") not in TYPES:
        raise Ineligible(f"data type {designators[0].get('DataType')}")
    found[_designator(designators[0])].append((function, literals))


def _leaves(apply: ET.Element, found: dict, leaves: list[ET.Element]) -> None:
    if apply.get("FunctionId", "") in LOGIC:
        for child in _children(apply):
            if child.tag != Q + "Apply":
                raise Ineligible("a logical function over a non-Apply")
            _leaves(child, found, leaves)
        return
    _comparison(apply, found)
    leaves.append(apply)


class Policy:
    """A parsed benchmark policy: what it reads, and the atoms it decides by."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.root = ET.fromstring(text)
        self.found: dict[Designator, list[tuple[str, list[str]]]] = defaultdict(list)
        self.reasons: list[str] = []
        self.atoms: list[tuple[str, ET.Element]] = []
        if any(True for _ in self.root.iter(Q + "AttributeSelector")):
            self.reasons.append("an AttributeSelector")
        for match in self.root.iter(Q + "Match"):
            function = match.get("MatchId", "")
            designator = match.find(Q + "AttributeDesignator")
            value = match.find(Q + "AttributeValue")
            if designator is None or value is None or function not in EQUAL | ORDER:
                self.reasons.append(f"match {function.rsplit(':', 1)[-1]}")
                continue
            if designator.get("DataType") not in TYPES:
                self.reasons.append(f"data type {designator.get('DataType')}")
                continue
            self.found[_designator(designator)].append((function, [_literal(value)]))
            self.atoms.append(("match", match))
        for condition in self.root.iter(Q + "Condition"):
            for child in _children(condition):
                if child.tag != Q + "Apply":
                    self.reasons.append(f"condition is a {child.tag.replace(Q, '')}")
                    continue
                leaves: list[ET.Element] = []
                try:
                    _leaves(child, self.found, leaves)
                except Ineligible as why:
                    self.reasons.append(str(why))
                    continue
                self.atoms.extend(("condition", leaf) for leaf in leaves)

    def candidates(self) -> dict[Designator, list[str | None]]:
        """Every literal, every threshold's neighbours, a fresh value, and absence."""

        out: dict[Designator, list[str | None]] = {}
        for designator, uses in sorted(self.found.items()):
            kind = designator[2]
            values = sorted({v for _, literals in uses for v in literals})
            if kind == INTEGER:
                numbers = {int(v) for v in values}
                for function, literals in uses:
                    if function in ORDER:
                        numbers |= {int(v) + d for v in literals for d in (-1, 0, 1)}
                fresh = max(numbers, default=0) + 1000
                ordered = [str(n) for n in sorted(numbers | {fresh})]
            elif kind == BOOLEAN:
                ordered = ["false", "true"]
            elif kind == ANYURI:
                ordered = [*values, "urn:trustweave:fresh"]
            else:
                ordered = [*values, "tw-fresh-value"]
            out[designator] = [*ordered, ABSENT]
        return out

    def cells(self) -> int:
        return math.prod(len(c) for c in self.candidates().values()) if self.found else 1


def _escape(value: str) -> str:
    return (
        value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def request_xml(values: dict[Designator, list[str]]) -> str:
    """A XACML 3.0 request on one line, with the constant attribute no policy reads."""

    by_category: dict[str, list[str]] = defaultdict(list)
    for (category, attribute, kind), given in sorted(values.items()):
        if not given:
            continue
        bag = "".join(
            f'<AttributeValue DataType="{kind}">{_escape(v)}</AttributeValue>' for v in given
        )
        by_category[category].append(
            f'<Attribute AttributeId="{_escape(attribute)}" IncludeInResult="false">'
            f"{bag}</Attribute>"
        )
    category, attribute, kind, value = UNREAD
    by_category[category].append(
        f'<Attribute AttributeId="{attribute}" IncludeInResult="false">'
        f'<AttributeValue DataType="{kind}">{value}</AttributeValue></Attribute>'
    )
    body = "".join(
        f'<Attributes Category="{_escape(c)}">{"".join(a)}</Attributes>'
        for c, a in sorted(by_category.items())
    )
    head = f'<Request xmlns="{NS}" CombinedDecision="false" ReturnPolicyIdList="false">'
    return f"{head}{body}</Request>"


def with_unread(request: str) -> str:
    """One of XPA's requests with the constant attribute added, like every request decided."""

    category, attribute, kind, value = UNREAD
    block = (
        f'<Attributes Category="{category}"><Attribute AttributeId="{attribute}" '
        f'IncludeInResult="false"><AttributeValue DataType="{kind}">{value}</AttributeValue>'
        f"</Attribute></Attributes>"
    )
    return (
        request.replace("</Request>", block + "</Request>", 1)
        if "</Request>" in request
        else request
    )


def atom_policy(kind: str, element: ET.Element, index: int) -> str:
    """One atom as its own policy: one Permit rule whose target or condition is the atom."""

    inner = ET.tostring(element, encoding="unicode")
    if kind == "match":
        target = f"<Target><AnyOf><AllOf>{inner}</AllOf></AnyOf></Target>"
        rule = f'<Rule RuleId="atom" Effect="Permit">{target}</Rule>'
    else:
        rule = f'<Rule RuleId="atom" Effect="Permit"><Condition>{inner}</Condition></Rule>'
    return (
        f'<Policy xmlns="{NS}" PolicyId="tw-atom-{index}" Version="1.0" '
        f'RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">'
        f"<Target/>{rule}</Policy>"
    )


# ---------------------------------------------------------------------------------------
# Running XPA and Balana
# ---------------------------------------------------------------------------------------


def xpa_mutants(tools: Tools, text: str, scratch: Path) -> list[tuple[str, str, Path]]:
    """XPA's mutants of the policy: (name, operator, file), in name order."""

    folder = scratch / "mutation"
    folder.mkdir(parents=True, exist_ok=True)
    policy = folder / "policy.xml"
    policy.write_text(text, encoding="utf-8")
    subprocess.run(
        [tools.java, "-cp", tools.xpa_classpath, "XpaMutants", str(policy)],
        check=True,
        capture_output=True,
        text=True,
        timeout=GENERATOR_TIMEOUT,
        cwd=folder,
    )
    found = []
    for path in sorted((folder / "mutants").glob("policy_*.xml")):
        name = path.stem.removeprefix("policy_")
        found.append((name, re.match(r"[A-Z]+", name).group(0), path))
    return found


def restore_target(path: Path) -> bool:
    """Give a policy the Target XACML 3.0 requires of it, empty, if the file has none.

    XPA's PTT writes its mutant without one; its documentation says the mutant is the policy
    "applied to all requests", which is what an empty Target means. Balana reads such a file but
    fails evaluating it, so the mutant is given the empty Target XPA describes.
    """

    root = ET.fromstring(path.read_text(encoding="utf-8-sig"))
    if root.tag != Q + "Policy" or root.find(Q + "Target") is not None:
        return False
    preamble = (Q + "Description", Q + "PolicyIssuer", Q + "PolicyDefaults")
    position = next((i for i, child in enumerate(root) if child.tag not in preamble), len(root))
    root.insert(position, ET.Element(Q + "Target"))
    path.write_text(ET.tostring(root, encoding="unicode"), encoding="utf-8")
    return True


def xpa_suite(tools: Tools, policy: Path, criterion: str, scratch: Path) -> dict[str, Any]:
    """One of XPA's suites for the policy, generated as XPA's test panel generates it."""

    work = scratch / f"suite-{criterion}"
    (work / "z3" / "build").mkdir(parents=True, exist_ok=True)
    for binary in tools.z3.iterdir():
        shutil.copy(binary, work / "z3" / "build" / binary.name)
    try:
        done = subprocess.run(
            [tools.java, "-cp", tools.xpa_classpath, "XpaSuites", str(policy), criterion],
            capture_output=True,
            text=True,
            timeout=GENERATOR_TIMEOUT,
            cwd=work,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return {"status": "over the time limit", "requests": []}
    requests = [
        line[len("REQUEST ") :] for line in done.stdout.splitlines() if line.startswith("REQUEST ")
    ]
    if done.returncode != 0:
        return {"status": "generator failed: " + done.stderr.strip()[-300:], "requests": requests}
    return {"status": "generated", "requests": [with_unread(r) for r in requests]}


def decide_matrix(
    tools: Tools, requests: list[str], policies: list[Path], scratch: Path
) -> list[str | None]:
    """For each policy, one letter per request (P, D, N or I); None if Balana cannot read it."""

    listing = scratch / "requests.txt"
    listing.write_text("\n".join(requests) + "\n", encoding="utf-8")
    commands = [f"REQUESTS {listing}", *(f"POLICY {p}" for p in policies)]
    done = subprocess.run(
        [
            tools.java,
            "-Dorg.ops4j.pax.logging.DefaultServiceLog.level=ERROR",
            "-cp",
            tools.balana_classpath,
            "XacmlMatrix",
        ],
        input="\n".join(commands) + "\n",
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    answers: list[str | None] = []
    for line in done.stdout.splitlines():
        if line.startswith("DECISIONS "):
            answers.append(line[len("DECISIONS ") :])
        elif line.startswith(("UNLOADABLE", "UNEVALUABLE")):
            answers.append(None)
    if len(answers) != len(policies):
        raise RuntimeError(
            f"{len(answers)} answers for {len(policies)} policies: {done.stderr[-400:]}"
        )
    for answer in answers:
        if answer is not None and len(answer) != len(requests):
            raise RuntimeError("a decision row of the wrong length")
    return answers


# ---------------------------------------------------------------------------------------
# One policy
# ---------------------------------------------------------------------------------------


def _drawn(
    candidates: dict[Designator, list[str | None]], generator: random.Random, bags: bool
) -> dict[Designator, list[str]]:
    values: dict[Designator, list[str]] = {}
    for index, (designator, options) in enumerate(candidates.items()):
        present = [o for o in options if o is not None]
        if bags:
            count = generator.randint(0, 3)
            values[designator] = sorted({generator.choice(present) for _ in range(count)})
            continue
        if generator.random() < 0.25:
            values[designator] = []
            continue
        kind = designator[2]
        if generator.random() < 0.5 or kind == BOOLEAN:
            values[designator] = [generator.choice(present)]
        elif kind == INTEGER:
            values[designator] = [str(int(generator.choice(present)) + generator.randint(-2, 2))]
        else:
            values[designator] = [f"tw-drawn-{index}-{generator.randrange(10**6)}"]
    return values


def analyse_policy(tools: Tools, name: str, text: str, scratch: Path) -> dict[str, Any]:
    ees = _load("exact_evaluation_study")
    policy = Policy(text)
    record: dict[str, Any] = {"policy": name}
    if policy.reasons:
        record["status"] = "not exact-eligible"
        record["reasons"] = sorted(set(policy.reasons))
        return record
    candidates = policy.candidates()
    record["designators"] = len(candidates)
    space = list(itertools.product(*candidates.values()))
    if len(space) > CAP:
        record.update(status="over the cell cap", cells=len(space))
        return record
    keys = list(candidates)
    cells = [
        request_xml({k: ([v] if v is not None else []) for k, v in zip(keys, cell, strict=True)})
        for cell in space
    ]
    generator = random.Random(f"{SEED}:{name}")
    drawn = [request_xml(_drawn(candidates, generator, bags=False)) for _ in range(DRAWS)]
    bags = [request_xml(_drawn(candidates, generator, bags=True)) for _ in range(DRAWS)]

    original = scratch / "policy.xml"
    original.write_text(text, encoding="utf-8")
    mutants = xpa_mutants(tools, text, scratch)
    record["targets_restored"] = [m for m, _, path in mutants if restore_target(path)]
    suites = {criterion: xpa_suite(tools, original, criterion, scratch) for criterion in CRITERIA}
    suite_requests = [r for c in CRITERIA for r in suites[c]["requests"]]

    atoms = []
    for index, (kind, element) in enumerate(policy.atoms):
        path = scratch / f"atom-{index}.xml"
        path.write_text(atom_policy(kind, element, index), encoding="utf-8")
        atoms.append(path)
    requests = [*cells, *drawn, *suite_requests, *bags]
    rows = decide_matrix(tools, requests, [original, *(p for _, _, p in mutants), *atoms], scratch)
    reference = rows[0]
    if reference is None:
        record["status"] = "Balana cannot read the policy"
        return record
    n_cells, n_drawn, n_suite = len(cells), len(drawn), len(suite_requests)
    span_cells = range(n_cells)
    span_checks = range(n_cells, n_cells + n_drawn + n_suite)
    span_bags = range(n_cells + n_drawn + n_suite, len(requests))
    atom_rows = rows[1 + len(mutants) :]
    if any(row is None for row in atom_rows):
        record["status"] = "Balana cannot read an atom"
        return record

    def signature(position: int) -> str:
        return "".join(row[position] for row in atom_rows)

    classes: dict[str, list[int]] = defaultdict(list)
    for position in span_cells:
        classes[signature(position)].append(position)
    by_decision: dict[str, list[int]] = defaultdict(list)
    for position in span_cells:
        by_decision[reference[position]].append(position)
    record.update(
        cells=n_cells,
        atoms=len(atoms),
        quotient_classes=len(classes),
        decisions=len(by_decision),
        mutants=len(mutants),
        suites={c: {"status": s["status"], "size": len(s["requests"])} for c, s in suites.items()},
    )
    record["constant_on_classes"] = all(
        len({reference[p] for p in group}) == 1 for group in classes.values()
    )
    missing_classes = sum(1 for p in span_checks if signature(p) not in classes)

    scored: list[dict[str, Any]] = []
    missing: list[str] = []
    operators: Counter[str] = Counter()
    unrunnable = 0
    for (mutant, operator, _), row in zip(mutants, rows[1 : 1 + len(mutants)], strict=True):
        if row is None:
            unrunnable += 1
            continue
        hits = {p for p in span_cells if row[p] != reference[p]}
        if not hits:
            if any(row[p] != reference[p] for p in span_checks):
                missing.append(mutant)
            operators[operator + ":equivalent"] += 1
            scored.append(
                {
                    "mutant": mutant,
                    "operator": operator,
                    "status": "equivalent",
                    "bag_separates": any(row[p] != reference[p] for p in span_bags),
                }
            )
            continue
        operators[operator + ":live"] += 1
        detection: dict[str, Fraction] = {
            "refinement": Fraction(1),
            "quotient": ees._detection(list(classes.values()), hits),
            "decision": ees._detection(list(by_decision.values()), hits),
            "random_quotient": ees._random_detection(
                n_cells, len(hits), min(len(classes), n_cells)
            ),
            "random_decision": ees._random_detection(
                n_cells, len(hits), min(len(by_decision), n_cells)
            ),
        }
        offset = n_cells + n_drawn
        for criterion in CRITERIA:
            size = len(suites[criterion]["requests"])
            span = range(offset, offset + size)
            offset += size
            if suites[criterion]["status"] != "generated":
                continue
            detection[criterion] = Fraction(int(any(row[p] != reference[p] for p in span)))
            detection[f"random_{criterion}"] = ees._random_detection(
                n_cells, len(hits), min(size, n_cells)
            )
        scored.append(
            {
                "mutant": mutant,
                "operator": operator,
                "status": "live",
                "difference": len(hits),
                "detection": detection,
            }
        )
    record.update(
        unrunnable=unrunnable,
        operators=dict(sorted(operators.items())),
        missing_cells_for=missing,
        requests_in_no_class=missing_classes,
    )
    if missing or missing_classes or not record["constant_on_classes"]:
        record["status"] = (
            "fails the completeness check"
            if (missing or missing_classes)
            else "decision not constant on a class"
        )
        return record
    record["status"] = "scored"
    record["scored"] = scored
    return record


# ---------------------------------------------------------------------------------------
# The study
# ---------------------------------------------------------------------------------------


def exact_sign_flip(differences: list[float]) -> float:
    """Two-sided p over every one of the 2^n sign patterns."""

    observed = abs(statistics.fmean(differences))
    extreme = 0
    total = 0
    for signs in itertools.product((1, -1), repeat=len(differences)):
        total += 1
        if (
            abs(statistics.fmean(s * d for s, d in zip(signs, differences, strict=True)))
            >= observed - 1e-12
        ):
            extreme += 1
    return extreme / total


def holm(pvalues: dict[str, float]) -> dict[str, float]:
    ordered = sorted(pvalues.items(), key=lambda kv: kv[1])
    adjusted: dict[str, float] = {}
    running = 0.0
    for rank, (key, value) in enumerate(ordered):
        running = max(running, min(1.0, (len(ordered) - rank) * value))
        adjusted[key] = running
    return adjusted


def policy_means(record: dict[str, Any]) -> dict[str, Fraction]:
    live = [m["detection"] for m in record["scored"] if m["status"] == "live"]
    keys = set.intersection(*(set(d) for d in live)) if live else set()
    return {k: sum((d[k] for d in live), Fraction(0)) / len(live) for k in keys}


def compare(records: list[dict[str, Any]]) -> dict[str, Any]:
    ees = _load("exact_evaluation_study")
    means = [policy_means(r) for r in records if any(m["status"] == "live" for m in r["scored"])]
    families: dict[str, dict[str, Any]] = {"H1": {}, "H2": {}}
    raw: dict[str, dict[str, float]] = {"H1": {}, "H2": {}}
    for criterion in CRITERIA:
        for family, left, right in (
            ("H1", "quotient", criterion),
            ("H2", criterion, f"random_{criterion}"),
        ):
            pairs = [(m[left], m[right]) for m in means if left in m and right in m]
            if len(pairs) < 2:
                continue
            exact = [a - b for a, b in pairs]
            differences = [float(d) for d in exact]
            low, high = ees.bootstrap_interval(differences, seed=SEED)
            raw[family][criterion] = exact_sign_flip(differences)
            families[family][criterion] = {
                "strategies": [left, right],
                "policies": len(differences),
                "mean_difference": round(statistics.fmean(differences), 6),
                "bootstrap_95": [round(low, 6), round(high, 6)],
                "p_value": round(raw[family][criterion], 4),
                "wins": sum(1 for d in exact if d > 0),
                "ties": sum(1 for d in exact if d == 0),
                "losses": sum(1 for d in exact if d < 0),
            }
    for family in families:
        for criterion, adjusted in holm(raw[family]).items():
            families[family][criterion]["holm_p"] = round(adjusted, 4)
    return families


def oracle(tools: Tools) -> dict[str, Any]:
    """The harness on Balana's own conformance cases, as Balana's test suite runs them."""

    base = tools.folder / "balana" / CONFORMANCE
    run_by_balana = {
        **{f"IIA{i:03d}": True for i in range(1, 22) if i not in (2, 4, 14)},
        **{f"IIB{i:03d}": True for i in range(1, 54) if i not in (28, 29)},
        **{
            f"IIC{i:03d}": True
            for i in range(1, 233)
            if i not in (3, 12, 14, 23, 54, 55, 88, 89, 92, 93, 98, 99, 105)
        },
        **{f"IID{i:03d}": True for i in range(1, 29)},
        **{f"IIIA{i:03d}": True for i in range(1, 29)},
    }
    cases: list[tuple[str, Path, str, str]] = []
    for version, suffix in (("2", ".xml"), ("3", ".xacml3.xml")):
        for request in sorted((base / version / "requests").glob(f"*Request{suffix}")):
            case = request.name[: -len(f"Request{suffix}")]
            if case not in run_by_balana:
                continue
            policies = sorted((base / version / "policies").glob(f"{case}Policy*{suffix}"))
            response = base / version / "responses" / f"{case}Response{suffix}"
            expected = re.findall(
                r"<Decision>\s*(\w+)\s*</Decision>", response.read_text("utf-8-sig")
            )
            if len(policies) != 1 or len(expected) != 1:
                continue
            text = re.sub(r"^\s*<\?xml[^>]*\?>", "", request.read_text("utf-8-sig"))
            letter = {"Permit": "P", "Deny": "D", "NotApplicable": "N", "Indeterminate": "I"}[
                expected[0]
            ]
            cases.append((case, policies[0], re.sub(r"\s*\n\s*", " ", text.strip()), letter))
    with tempfile.TemporaryDirectory() as directory:
        # Every request against every policy in one run; each case is its own diagonal entry.
        rows = decide_matrix(tools, [c[2] for c in cases], [c[1] for c in cases], Path(directory))
    disagreements = [
        case
        for index, ((case, _, _, letter), row) in enumerate(zip(cases, rows, strict=True))
        if row is None or row[index] != letter
    ]
    return {
        "cases_balana_runs_with_one_policy_and_one_result": len(cases),
        "agree": len(cases) - len(disagreements),
        "disagree": len(disagreements),
        "disagreements": disagreements,
    }


def _policy_text(tools: Tools, name: str) -> str:
    stem = name.removesuffix(".xml")
    return (tools.xpa / "Experiments" / stem / name).read_text(encoding="utf-8-sig")


def _run(task: tuple[str, str, str]) -> dict[str, Any]:
    folder, name, text = task
    tools = Tools(Path(folder))
    with tempfile.TemporaryDirectory() as directory:
        return analyse_policy(tools, name, text, Path(directory))


def summarise(records: list[dict[str, Any]]) -> dict[str, Any]:
    scored = [r for r in records if r["status"] == "scored"]
    live = [m for r in scored for m in r["scored"] if m["status"] == "live"]
    equivalent = [m for r in scored for m in r["scored"] if m["status"] == "equivalent"]
    keys = [*STRATEGIES, *CRITERIA, *(f"random_{c}" for c in CRITERIA)]
    by_policy = {
        r["policy"]: {k: round(float(v), 6) for k, v in policy_means(r).items()} for r in scored
    }
    pooled = {
        k: round(statistics.fmean(float(m["detection"][k]) for m in live if k in m["detection"]), 6)
        for k in keys
        if any(k in m["detection"] for m in live)
    }
    mean_over_policies = {
        k: round(statistics.fmean(v[k] for v in by_policy.values() if k in v), 6)
        for k in keys
        if any(k in v for v in by_policy.values())
    }
    sizes = {
        c: round(
            statistics.fmean(
                r["suites"][c]["size"] for r in scored if r["suites"][c]["status"] == "generated"
            ),
            3,
        )
        for c in CRITERIA
        if any(r["suites"][c]["status"] == "generated" for r in scored)
    }
    return {
        "policies_scored": len(scored),
        "statuses": dict(sorted(Counter(r["status"] for r in records).items())),
        "mutants": {
            "live": len(live),
            "equivalent": len(equivalent),
            "unrunnable": sum(r.get("unrunnable", 0) for r in scored),
        },
        "equivalent_by_operator": dict(sorted(Counter(m["operator"] for m in equivalent).items())),
        "live_by_operator": dict(sorted(Counter(m["operator"] for m in live).items())),
        "bag_check": {
            "equivalent_mutants_a_bag_request_separates": sum(
                1 for m in equivalent if m["bag_separates"]
            )
        },
        "mean_over_policies": mean_over_policies,
        "pooled_over_mutants": pooled,
        "mean_suite_size": {
            **sizes,
            "quotient": round(statistics.fmean(r["quotient_classes"] for r in scored), 3)
            if scored
            else None,
            "decision": round(statistics.fmean(r["decisions"] for r in scored), 3)
            if scored
            else None,
        },
        "by_policy": by_policy,
    }


def study(tools: Tools, workers: int, development: list[Path] | None = None) -> dict[str, Any]:
    """The protocol's population, or development files named on the command line."""

    eligible, excluded = population()
    if development:
        tasks = [
            (str(tools.folder), p.name, p.read_text(encoding="utf-8-sig")) for p in development
        ]
    else:
        require_protocol()
        tasks = [(str(tools.folder), name, _policy_text(tools, name)) for name in eligible]
    context = multiprocessing.get_context("spawn")
    with concurrent.futures.ProcessPoolExecutor(workers, mp_context=context) as pool:
        records = list(pool.map(_run, tasks))
    scored = [r for r in records if r["status"] == "scored"]
    summary = summarise(records)
    hypotheses = compare(scored)
    for record in scored:
        for mutant in record["scored"]:
            if "detection" in mutant:
                mutant["detection"] = {
                    k: round(float(v), 6) for k, v in mutant["detection"].items()
                }
    return {
        "schema_version": "v1",
        "protocol_sha256": PROTOCOL_SHA256,
        "engine": "balana 1.2.24",
        "seed": SEED,
        "resamples": RESAMPLES,
        "max_cells": CAP,
        "draws": DRAWS,
        "tools": tools.versions(),
        "oracle": oracle(tools),
        "population": {"eligible": eligible, "excluded": excluded},
        "deviations": DEVIATIONS,
        "summary": summary,
        "hypotheses": hypotheses,
        "policies": records,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    setup = sub.add_parser("setup")
    setup.add_argument("--tools", type=Path, required=True)
    run = sub.add_parser("study")
    run.add_argument("--tools", type=Path, required=True)
    run.add_argument("--workers", type=int, default=4)
    run.add_argument(
        "--development",
        type=Path,
        nargs="*",
        help="policy files outside the population, for developing the instrument",
    )
    run.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    tools = Tools(args.tools)
    if args.command == "setup":
        tools.setup()
        print(json.dumps(tools.versions(), indent=1))
        return 0
    result = study(tools, args.workers, args.development)
    text = json.dumps(result, indent=1)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
