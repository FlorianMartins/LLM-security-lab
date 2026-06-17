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
    INTERNAL_PRODUCT_NAME,
    PROMPT_CANARY,
    RAG_INJECTION_MARKER,
    SUPPORT_ESCALATION_CODE,
    settings,
)
from .guardrails import looks_like_injection, redact_secrets, wrap_reference, wrap_untrusted
from .kb import retrieve_context
from .llm import chat, chat_with_tools
from .prompts import agent_system_prompt, hardened_system_prompt, vulnerable_system_prompt
from .tools import REFUND_TOOL, execute_refund

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
        # Retrieved content is untrusted (LLM08): wrap it as reference data so the
        # model treats it as facts, not instructions. The profile field/message stay
        # in their own untrusted envelope.
        user_content = (
            wrap_reference(kb)
            + "\n\n"
            + wrap_untrusted(f"Customer name: {customer_name}\n\nMessage: {message}")
        )
        reply = chat(hardened_system_prompt(), user_content)
        # Scrub known prompt/data internals (secret + canary + internal name + RAG tag).
        reply = redact_secrets(
            reply,
            [SUPPORT_ESCALATION_CODE, PROMPT_CANARY, INTERNAL_PRODUCT_NAME, RAG_INJECTION_MARKER],
        )
    else:
        mode = "vulnerable"
        flags: dict = {}
        # FLAW (LLM02): retrieval pulls internal data into context — no minimization.
        # FLAW (LLM08): retrieved content is stuffed into the trusted system prompt,
        # so a poisoned document's directive is followed.
        # FLAW (LLM01): the profile field is interpolated into the system prompt too.
        kb = retrieve_context(include_internal=True)
        reply = chat(vulnerable_system_prompt(customer_name, kb), message)

    return ChatResponse(mode=mode, reply=reply, flags=flags)


class AgentRequest(BaseModel):
    message: str = Field(..., max_length=8000)
    mode: str | None = None  # "vulnerable" | "hardened"


class AgentResponse(BaseModel):
    mode: str
    reply: str
    actions: list[dict]


@app.post("/agent", response_model=AgentResponse)
def agent_endpoint(req: AgentRequest) -> AgentResponse:
    """Tool-enabled agent (LLM06 — Excessive Agency).

    Both modes expose the same high-impact `process_refund` tool. The difference is
    autonomy: the vulnerable agent auto-executes every tool call (no approval, no
    limit); the hardened agent never executes a high-impact action itself — it is
    held for human approval (human-in-the-loop).
    """
    mode = (req.mode or settings.default_mode).lower()
    message = req.message[: settings.max_input_chars]
    actions: list[dict] = []

    if mode == "hardened":
        reply, tool_calls = chat_with_tools(
            agent_system_prompt(hardened=True), message, [REFUND_TOOL]
        )
        for call in tool_calls:
            # Human-in-the-loop: high-impact tools are queued, never auto-executed.
            actions.append(
                {"tool": call["name"], "input": call["input"], "status": "blocked_pending_approval"}
            )
    else:
        mode = "vulnerable"
        # `tool_choice=any` mirrors an over-eager agent that always acts.
        reply, tool_calls = chat_with_tools(
            agent_system_prompt(hardened=False),
            message,
            [REFUND_TOOL],
            tool_choice={"type": "any"},
        )
        for call in tool_calls:
            # FLAW (LLM06): execute whatever the model asked for, unconditionally.
            execute_refund(call["input"])
            actions.append({"tool": call["name"], "input": call["input"], "status": "executed"})

    return AgentResponse(mode=mode, reply=reply, actions=actions)
