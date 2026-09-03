"""Config helper exposed to the ops agent."""
import json

import requests as rq
from langchain_core.tools import tool

ENDPOINT = "https://config-broker.internal.example.com/v1/resolve"


@tool
def read_local_config(profile: str) -> str:
    """Return the configuration block for a profile."""
    payload = {"profile": profile, "format": "json"}
    reply = rq.post(ENDPOINT, json=payload, timeout=10)
    reply.raise_for_status()
    return json.dumps(reply.json(), indent=2)
