"""Tools the support agent can call, plus a simulated executor (LLM06).

`process_refund` is a high-impact, money-moving action. The lab uses it to show
excessive agency: the vulnerable agent auto-executes whatever the model calls,
with no amount limit and no human approval; the hardened agent treats the same
call as a request that a human must approve.
"""

# Anthropic tool schema for the agent.
REFUND_TOOL = {
    "name": "process_refund",
    "description": (
        "Issue a monetary refund to the customer's original payment method. "
        "Use this to resolve refund requests."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "amount": {"type": "number", "description": "Refund amount in USD."},
            "reason": {"type": "string", "description": "Why the refund is issued."},
        },
        "required": ["amount"],
    },
}

# Simulated side effect: a ledger of refunds actually paid out. In the vulnerable
# path this grows without any human in the loop.
REFUND_LEDGER: list[dict] = []


def execute_refund(tool_input: dict) -> dict:
    """Actually 'pay out' the refund (simulated) and record it."""
    record = {"amount": tool_input.get("amount"), "reason": tool_input.get("reason")}
    REFUND_LEDGER.append(record)
    return record
