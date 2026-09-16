"""Two renderings that a reader acts on, and the separators inside them.

`_fallback_subject` gives an older artifact a distinguishing identity when it carries no
structured subject. The schema versions it recognises are a literal set, and dropping one
silently demotes every artifact of that version to a `legacy_message` subject -- which is
the collapse into one risk identity that structured subjects were introduced to stop.
v1alpha2 was named in the set but no test entered through it.

`_render_summary` joins the incomplete-analysis reasons into text a reviewer reads. The
separators were unasserted because every test that reached the section supplied a single
reason, and a one-element join renders identically whatever the separator is. Both
renderings are therefore exercised with two reasons.
"""

from __future__ import annotations

from typing import Any

import pytest

from trustweave import risk as risk_module
from trustweave.commands.ci import _render_summary

# ---------------------------------------------------------------------------------------
# _fallback_subject: each recognised schema version keeps its own identity
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "schema_version",
    [
        "trustweave.dev/policy-review/v1alpha1",
        "trustweave.dev/policy-review/v1alpha2",
    ],
)
def test_a_policy_review_of_either_version_is_identified_by_its_policy(
    schema_version: str,
) -> None:
    """Both versions are named in the set, so both must reach the policy identity."""

    subject = risk_module._fallback_subject({"policy": "support"}, schema_version, "message")

    assert subject == {"policy": "support"}


def test_an_unrecognised_schema_version_falls_back_to_the_message() -> None:
    subject = risk_module._fallback_subject(
        {"policy": "support"}, "trustweave.dev/something-else/v1alpha1", "message"
    )

    assert subject == {"legacy_message": "message"}


def test_a_policy_review_without_a_policy_string_falls_back_to_the_message() -> None:
    subject = risk_module._fallback_subject(
        {"policy": 7}, "trustweave.dev/policy-review/v1alpha2", "message"
    )

    assert subject == {"legacy_message": "message"}


# ---------------------------------------------------------------------------------------
# _render_summary: the separators between incomplete reasons
# ---------------------------------------------------------------------------------------


def _summary(incomplete: list[str]) -> dict[str, Any]:
    return {
        "status": "passed",
        "generated_at": "2026-09-16T00:00:00+00:00",
        "artifacts": ["a.json", "b.json"],
        "incomplete_analyses": incomplete,
    }


def test_markdown_puts_each_incomplete_reason_on_its_own_line() -> None:
    """Two reasons, because a one-element join hides the separator entirely."""

    rendered = _render_summary(_summary(["chain budget reached", "discovery declined"]), "markdown")

    assert "## Incomplete analyses\n\n- chain budget reached\n- discovery declined\n\n" in rendered


def test_the_text_summary_separates_incomplete_reasons_with_a_semicolon() -> None:
    rendered = _render_summary(_summary(["chain budget reached", "discovery declined"]), "text")

    assert "\nIncomplete analyses: chain budget reached; discovery declined" in rendered


def test_a_summary_with_nothing_incomplete_renders_no_such_section() -> None:
    rendered = _render_summary(_summary([]), "markdown")

    assert "Incomplete analyses" not in rendered
