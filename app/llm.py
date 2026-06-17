"""Thin wrapper around the Anthropic Messages API.

Uses the official `anthropic` SDK. The client reads the API key from the
ANTHROPIC_API_KEY environment variable — we never pass a key in code.
"""

import anthropic

from .config import settings

_client = anthropic.Anthropic()


def chat(system: str, user_content: str, *, max_tokens: int = 512) -> str:
    """Single-turn completion. Returns the concatenated text of the reply."""
    response = _client.messages.create(
        model=settings.model,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user_content}],
    )
    return "".join(block.text for block in response.content if block.type == "text")


def chat_with_tools(
    system: str,
    user_content: str,
    tools: list[dict],
    *,
    tool_choice: dict | None = None,
    max_tokens: int = 512,
) -> tuple[str, list[dict]]:
    """Single-turn completion with tool use.

    Returns (text, tool_calls) where tool_calls is a list of
    {"name": str, "input": dict} for each tool the model decided to invoke.
    """
    kwargs: dict = {
        "model": settings.model,
        "max_tokens": max_tokens,
        "system": system,
        "tools": tools,
        "messages": [{"role": "user", "content": user_content}],
    }
    if tool_choice is not None:
        kwargs["tool_choice"] = tool_choice
    response = _client.messages.create(**kwargs)
    text = "".join(b.text for b in response.content if b.type == "text")
    tool_calls = [
        {"name": b.name, "input": b.input} for b in response.content if b.type == "tool_use"
    ]
    return text, tool_calls
