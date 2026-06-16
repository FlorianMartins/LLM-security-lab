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
