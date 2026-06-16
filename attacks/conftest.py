"""Shared pytest fixtures for the red-team attack suite."""

import os

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="session")
def client() -> TestClient:
    """A TestClient that drives the real FastAPI app (which calls the real LLM).

    Skips the whole suite when no API key is present, so CI lint + secret-scan
    still run on forks/PRs without access to the ANTHROPIC_API_KEY secret.
    """
    if not os.getenv("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY not set — skipping live LLM attack suite")
    return TestClient(app)
