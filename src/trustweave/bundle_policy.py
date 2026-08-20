"""Normalization of policy payloads rendered by current bundle artifacts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def normalize_rendered_policy(value: Mapping[str, Any]) -> dict[str, Any]:
    """Convert a generated current-bundle policy to the policy parser's absence convention.

    The current bundle schema renders an absent approval control as JSON ``null``. The policy
    input schema instead represents absence by omitting the key. Non-null payloads intentionally
    remain untouched so downstream policy validation rejects malformed control objects.
    """

    rendered = dict(value)
    if "approval_control" in rendered and rendered["approval_control"] is None:
        del rendered["approval_control"]
    return rendered
