"""Central configuration, read from environment variables.

Nothing secret lives here except a *fake* planted credential used only to
demonstrate system-prompt leakage (LLM07) and sensitive-information
disclosure (LLM02). The real API key is read by the Anthropic SDK from the
ANTHROPIC_API_KEY environment variable and never appears in code.
"""

import os
from dataclasses import dataclass

# A FAKE internal credential, deliberately planted in the bot's context so the
# lab can show what an attacker can pull out of it. It is not a real secret.
SUPPORT_ESCALATION_CODE = "ACME-INTERNAL-7731"

# A benign "canary" string embedded in the system prompt. Unlike the escalation
# code, it carries no security charge, so an aligned model has no safety reflex to
# withhold it — which makes it a reliable probe for system-prompt leakage (a real
# canary-token technique). The lesson it teaches: ANY content embedded in the
# prompt can escape to the user, so secrets must never live there (see LLM07).
PROMPT_CANARY = "ORCHID-DELTA-19"


@dataclass(frozen=True)
class Settings:
    # Default to the cheapest current Claude model — the attack suite makes only
    # a handful of small calls, so this keeps a full run at a few cents.
    # Override with LLM_MODEL=claude-opus-4-8 for the most capable model.
    model: str = os.getenv("LLM_MODEL", "claude-haiku-4-5")
    default_mode: str = os.getenv("DEFAULT_MODE", "vulnerable")
    max_input_chars: int = int(os.getenv("MAX_INPUT_CHARS", "4000"))


settings = Settings()
