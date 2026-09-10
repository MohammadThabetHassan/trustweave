"""The frameworks a third-party survey found, and the record of what it found.

docs/classifier-evaluation-v1.json measures precision on cases this project wrote. It
cannot measure coverage, because a registration form its authors did not know about
produces no case and no gap -- the tools are simply absent from the artifact.

Running discovery over real agent repositories is what surfaced two such forms, and they
were the largest coverage gaps in the analyzer. These tests pin the forms so neither can
regress to invisible again, and pin the survey figures the record quotes. The corpora are
not vendored, so the survey itself is not re-run here; the registration forms are asserted
against transcribed sources instead, which needs no network.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustweave.code_analysis import (
    BASE_TOOL_FRAMEWORKS,
    CREWAI_TOOL_DECORATORS,
    OPENAI_AGENTS_DECORATORS,
    analyze_sources,
)
from trustweave.code_sources import collect_python_sources

ROOT = Path(__file__).resolve().parents[1]
SURVEY = ROOT / "docs" / "wild-discovery-survey-v1.json"


def _single_tool(tmp_path: Path, source: str):
    (tmp_path / "agent.py").write_text(source, encoding="utf-8")
    tools, _ = analyze_sources(collect_python_sources(tmp_path))
    assert len(tools) == 1, [tool.name for tool in tools]
    return tools[0]


class TestOpenAIAgentsSDK:
    """328 tools in one repository were invisible because this form was not recognised."""

    @pytest.mark.parametrize("decorator", ["function_tool", "agents.function_tool"])
    def test_a_function_tool_is_discovered(self, tmp_path: Path, decorator: str) -> None:
        preamble = "import agents" if "." in decorator else "from agents import function_tool"
        source = (
            f"{preamble}\n"
            "import requests\n"
            "\n\n"
            f"@{decorator}\n"
            "def fetch_page(url: str) -> str:\n"
            '    """Fetch a page."""\n'
            "    return requests.get(url).text\n"
        )
        tool = _single_tool(tmp_path, source)

        assert tool.name == "fetch_page"
        assert tool.framework == "openai_agents_decorator"
        assert tool.proposed_action_class() == "external"

    def test_the_name_override_is_the_registered_name(self, tmp_path: Path) -> None:
        """The model is shown `fetch`, so reporting `fetch_page` is drift about nothing."""

        source = (
            "from agents import function_tool\n"
            "\n\n"
            '@function_tool(name_override="fetch")\n'
            "def fetch_page(url: str) -> str:\n"
            '    """Fetch a page."""\n'
            "    return url\n"
        )
        tool = _single_tool(tmp_path, source)

        assert tool.name == "fetch"
        assert tool.implementation == "fetch_page"

    def test_an_effect_reached_through_it_is_still_classified(self, tmp_path: Path) -> None:
        source = (
            "from agents import function_tool\n"
            "\n\n"
            "@function_tool\n"
            "def load_key(name: str) -> str:\n"
            '    """Load a key."""\n'
            "    with open('/home/agent/.ssh/id_rsa') as handle:\n"
            "        return handle.read()\n"
        )

        assert _single_tool(tmp_path, source).proposed_action_class() == "sensitive"


class TestCrewAI:
    """133 class-based tools in one repository were invisible, and 71 were mislabelled."""

    def test_a_crewai_decorator_is_not_reported_as_a_server_decorator(self, tmp_path: Path) -> None:
        """`server_tool_decorator` is documented as a lower-confidence guess about FastMCP."""

        source = (
            "from crewai.tools import tool\n"
            "import requests\n"
            "\n\n"
            '@tool("Fetch Page")\n'
            "def fetch_page(url: str) -> str:\n"
            '    """Fetch a page."""\n'
            "    return requests.get(url).text\n"
        )
        tool = _single_tool(tmp_path, source)

        assert tool.framework == "crewai_tool_decorator"
        assert tool.name == "Fetch Page"

    def test_a_crewai_class_tool_is_discovered(self, tmp_path: Path) -> None:
        source = (
            "from crewai.tools import BaseTool\n"
            "import requests\n"
            "\n\n"
            "class Fetch(BaseTool):\n"
            '    name: str = "Fetch Page"\n'
            '    description: str = "Fetch"\n'
            "\n"
            "    def _run(self, url: str) -> str:\n"
            "        return requests.get(url).text\n"
        )
        tool = _single_tool(tmp_path, source)

        assert tool.name == "Fetch Page"
        assert tool.framework == "crewai_base_tool_subclass"
        assert tool.implementation == "Fetch"
        assert tool.proposed_action_class() == "external"

    def test_the_framework_names_the_project_the_base_came_from(self) -> None:
        """A CrewAI tool reported as LangChain sends a reviewer to the wrong library."""

        assert BASE_TOOL_FRAMEWORKS["crewai.tools.BaseTool"] == "crewai"
        assert BASE_TOOL_FRAMEWORKS["langchain_core.tools.BaseTool"] == "langchain"

    def test_the_langchain_label_is_unchanged(self, tmp_path: Path) -> None:
        """It is published, so deriving it must not have renamed it."""

        source = (
            "from langchain_core.tools import BaseTool\n"
            "\n\n"
            "class Fetch(BaseTool):\n"
            '    name: str = "fetch_page"\n'
            "\n"
            "    def _run(self, url: str) -> str:\n"
            "        return url\n"
        )

        assert _single_tool(tmp_path, source).framework == "langchain_base_tool_subclass"


def test_the_decorator_tables_are_disjoint() -> None:
    """A decorator in two tables would report whichever framework was checked first."""

    assert not (OPENAI_AGENTS_DECORATORS & CREWAI_TOOL_DECORATORS)


@pytest.fixture(scope="module")
def survey() -> dict:
    return json.loads(SURVEY.read_text(encoding="utf-8"))


class TestSurveyRecord:
    def test_the_quoted_totals_hold(self, survey: dict) -> None:
        assert survey["corpora_surveyed"] == 9
        assert survey["tools_discovered"] == 1998

    def test_every_documented_registration_form_is_exercised(self, survey: dict) -> None:
        """A form nobody's code uses is a claim the survey cannot support."""

        assert set(survey["frameworks"]) >= {
            "openai_agents_decorator",
            "crewai_base_tool_subclass",
            "crewai_tool_decorator",
            "smolagents_decorator",
            "server_tool_decorator",
            "mcp_declared_tool",
            "mcp_call_tool",
            "langchain_tool_decorator",
            "langchain_base_tool_subclass",
            "semantic_kernel_decorator",
            "bound_plain_function",
        }

    def test_the_name_screen_reports_candidates_rather_than_verdicts(self, survey: dict) -> None:
        """It exists to find misses in unlabelled code, and it is not a classification rule.

        Every hit is a tool the analyzer called `read` whose name begins with a verb that
        would be odd for one. The five inspected were all mock tools in test suites that
        return a formatted string, so the reads were right and the names described intent
        -- which is the analyzer's own rule that a name is not behaviour, holding on code
        nobody here wrote.
        """

        assert survey["name_screen_hits"] == sum(
            len(entry["name_screen"]) for entry in survey["surveys"]
        )
        assert survey["name_screen_hits"] < survey["tools_discovered"] // 20

    def test_every_corpus_records_where_it_came_from(self, survey: dict) -> None:
        """The corpora are fetched rather than vendored, so the commit is the only anchor."""

        assert set(survey["corpus"]) == {entry["corpus"] for entry in survey["surveys"]}
        for provenance in survey["corpus"].values():
            assert provenance["remote"].startswith("https://")
            assert len(provenance["commit"]) == 40

    def test_the_forms_the_survey_found_are_present(self, survey: dict) -> None:
        assert survey["frameworks"]["openai_agents_decorator"] == 328
        assert survey["frameworks"]["crewai_base_tool_subclass"] == 133
        assert survey["frameworks"]["smolagents_decorator"] == 49

    def test_each_survey_accounts_for_its_own_tools(self, survey: dict) -> None:
        for entry in survey["surveys"]:
            assert sum(entry["frameworks"].values()) == entry["tools"]
            assert sum(entry["action_classes"].values()) == entry["tools"]


class TestReceiverDecorators:
    """`@agent.tool_plain` is 693 uses in one repository and did not end in `.tool`."""

    @pytest.mark.parametrize("attribute", ["tool", "tool_plain"])
    def test_a_decorator_taken_from_a_runtime_object_is_discovered(
        self, tmp_path: Path, attribute: str
    ) -> None:
        source = (
            "from pydantic_ai import Agent\n"
            "import requests\n"
            "\n\n"
            "agent = Agent('openai:gpt-4o')\n"
            "\n\n"
            f"@agent.{attribute}\n"
            "def fetch_page(url: str) -> str:\n"
            '    """Fetch a page."""\n'
            "    return requests.get(url).text\n"
        )
        tool = _single_tool(tmp_path, source)

        assert tool.name == "fetch_page"
        assert tool.proposed_action_class() == "external"

    def test_the_framework_is_recorded_as_the_shape_not_a_guess(self, tmp_path: Path) -> None:
        """Which library the receiver belongs to cannot be known from the source."""

        source = (
            "from mcp.server.fastmcp import FastMCP\n"
            "\n\n"
            "mcp = FastMCP('x')\n"
            "\n\n"
            "@mcp.tool()\n"
            "def fetch_page(url: str) -> str:\n"
            '    """Fetch a page."""\n'
            "    return url\n"
        )

        assert _single_tool(tmp_path, source).framework == "server_tool_decorator"


def test_a_smolagents_decorator_names_its_own_project(tmp_path: Path) -> None:
    """It resolves to a package, so it can be reported as itself."""

    source = (
        "from smolagents import tool\n"
        "\n\n"
        "@tool\n"
        "def fetch_page(url: str) -> str:\n"
        '    """Fetch a page."""\n'
        "    return url\n"
    )

    assert _single_tool(tmp_path, source).framework == "smolagents_decorator"
