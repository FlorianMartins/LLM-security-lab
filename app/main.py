"""FastAPI app exposing SupportBot in two modes: vulnerable and hardened.

POST /chat  {"message": "...", "mode": "vulnerable" | "hardened"}

The same endpoint serves both modes so the attack suite can fire identical
payloads at each and assert on the difference.
"""

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .config import SUPPORT_ESCALATION_CODE, settings
from .guardrails import looks_like_injection, redact_secrets, wrap_untrusted
from .llm import chat
from .prompts import hardened_system_prompt, vulnerable_system_prompt

app = FastAPI(title="Hivey LLM Security Lab", version="0.1.0")


class ChatRequest(BaseModel):
    message: str = Field(..., max_length=8000)
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

    if mode == "hardened":
        flags = {"injection_detected": looks_like_injection(message)}
        reply = chat(hardened_system_prompt(), wrap_untrusted(message))
        reply = redact_secrets(reply, [SUPPORT_ESCALATION_CODE])
    else:
        mode = "vulnerable"
        flags: dict = {}
        reply = chat(vulnerable_system_prompt(), message)

    return ChatResponse(mode=mode, reply=reply, flags=flags)
