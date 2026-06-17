"""OWASP LLM10 — Unbounded Consumption.

The attack is a resource-exhaustion request: an oversized prompt (and, more
generally, a flood of requests) that drives cost and latency without limit.

Unlike the other findings this is pure application logic, so most of it is
deterministic and needs no API key:
- Hardened mode rejects oversized input with HTTP 413 *before* any model call, and
  throttles requests per window (the rate limiter is unit-tested below with an
  injected clock).
- Vulnerable mode enforces neither, so the oversized request is accepted and the
  model is invoked (cost incurred). That single check needs the live API and is
  gated by the `client` fixture like the rest of the suite.
"""

from app.limits import SlidingWindowRateLimiter

# Comfortably over the hardened 2000-char cap, but small in absolute terms so the
# one vulnerable-mode model call stays cheap.
OVERSIZED = "A" * 3000


def test_llm10_oversized_rejected_in_hardened_mode(client):
    response = client.post("/chat", json={"message": OVERSIZED, "mode": "hardened"})
    assert response.status_code == 413, response.text


def test_llm10_oversized_accepted_in_vulnerable_mode(client):
    # No cap: the request is processed and the model is invoked → resources spent.
    response = client.post("/chat", json={"message": OVERSIZED, "mode": "vulnerable"})
    assert response.status_code == 200, response.text


def test_rate_limiter_throttles_after_limit():
    """Deterministic unit test of the throttle (no LLM, no API key)."""
    rl = SlidingWindowRateLimiter(max_calls=3, per_seconds=60)
    assert [rl.allow("k", now=t) for t in (0, 1, 2)] == [True, True, True]
    assert rl.allow("k", now=3) is False  # 4th call within the window → blocked
    assert rl.allow("k", now=61) is True  # window has slid → allowed again
