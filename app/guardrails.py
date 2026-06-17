"""Defensive helpers used only in hardened mode.

These are intentionally simple and readable — the point of the lab is to show
*which* mitigation stops *which* attack, not to ship a production WAF.
"""

import re

_INJECTION_PATTERNS = [
    r"ignore (?:all|the|your|any|previous|above|prior)",
    r"disregard (?:all|the|your|previous|above|prior)",
    r"forget (?:all|the|your|previous|everything)",
    r"you are (?:now|no longer)",
    r"system prompt",
    r"reveal (?:your|the) (?:instructions|prompt|rules|system)",
]
_INJECTION_RE = re.compile("|".join(_INJECTION_PATTERNS), re.IGNORECASE)


def looks_like_injection(text: str) -> bool:
    """Heuristic detection of common prompt-injection phrasings (for logging/alerting)."""
    return bool(_INJECTION_RE.search(text or ""))


def wrap_untrusted(user_text: str) -> str:
    """Delimit user input so the model can tell data from instructions.

    Strips any attempt to close the delimiter early before wrapping.
    """
    safe = (user_text or "").replace("</user_input>", "")
    return f"<user_input>\n{safe}\n</user_input>"


def wrap_reference(retrieved_text: str) -> str:
    """Delimit retrieved/RAG content as untrusted reference data (LLM08).

    Retrieved documents are not authored by us and may carry hidden instructions,
    so they get their own clearly-labelled, instruction-free envelope.
    """
    safe = (retrieved_text or "").replace("</reference_data>", "")
    return f"<reference_data>\n{safe}\n</reference_data>"


def redact_secrets(text: str, secrets: list[str]) -> str:
    """Last line of defense: never let a known secret leave the system (LLM02/LLM07)."""
    out = text
    for secret in secrets:
        if secret:
            out = out.replace(secret, "[REDACTED]")
    return out
