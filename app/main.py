"""FastAPI app exposing SupportBot in two modes: vulnerable and hardened.

POST /chat  {"message": "...", "customer_name": "...", "mode": "vulnerable" | "hardened"}

`customer_name` simulates an attacker-controllable profile field. In vulnerable
mode it is concatenated into the system prompt (the LLM01 flaw); in hardened mode
it stays in the user channel, framed as untrusted data. The same endpoint serves
both modes so the attack suite can fire identical payloads at each.
"""

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .config import (
    INTERNAL_PRODUCT_CODENAME,
    PROMPT_CANARY,
    SUPPORT_ESCALATION_CODE,
    settings,
)
from .guardrails import looks_like_injection, redact_secrets, wrap_untrusted
from .kb import retrieve_context
from .llm import chat
from .prompts import hardened_system_prompt, vulnerable_system_prompt

app = FastAPI(title="LLM Security Lab", version="0.1.0")


class ChatRequest(BaseModel):
    message: str = Field(..., max_length=8000)
    customer_name: str = Field("Guest", max_length=2000)
    mode: str | None = None  # "vulnerable" | "hardened"; defaults to settings.default_mode


class ChatResponse(BaseModel):
    mode: str
    reply: str
    flags: dict


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model": settings.model}


@app.post("/chat", response_model=ChatResponse)
def chat_endpoint(req: ChatRequest) -> ChatResponse:
    mode = (req.mode or settings.default_mode).lower()
    message = req.message[: settings.max_input_chars]
    customer_name = req.customer_name[: settings.max_input_chars]

    if mode == "hardened":
        flags = {
            "injection_detected": looks_like_injection(customer_name)
            or looks_like_injection(message)
        }
        # Data minimization: retrieve only customer-facing knowledge (no internal data).
        kb = retrieve_context(include_internal=False)
        # Untrusted data (incl. the profile field) stays in the user channel; the
        # trusted KB reference sits outside the <user_input> tags.
        user_content = (
            f"AcmeCorp knowledge base (reference):\n{kb}\n\n"
            + wrap_untrusted(f"Customer name: {customer_name}\n\nMessage: {message}")
        )
        reply = chat(hardened_system_prompt(), user_content)
        # Scrub known prompt/data internals (secret + canary + internal codename).
        reply = redact_secrets(
            reply, [SUPPORT_ESCALATION_CODE, PROMPT_CANARY, INTERNAL_PRODUCT_CODENAME]
        )
    else:
        mode = "vulnerable"
        flags: dict = {}
        # FLAW (LLM02): retrieval pulls internal data into context — no minimization.
        kb = retrieve_context(include_internal=True)
        user_content = f"AcmeCorp knowledge base (reference):\n{kb}\n\nUser message: {message}"
        # FLAW (LLM01): the profile field is interpolated into the trusted system prompt.
        reply = chat(vulnerable_system_prompt(customer_name), user_content)

    return ChatResponse(mode=mode, reply=reply, flags=flags)
