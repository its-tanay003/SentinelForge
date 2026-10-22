"""Pytest configuration and shared fixtures."""
import asyncio
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport

# The demo target apps
from demo_target.vulnerable_app import vulnerable_app, hardened_app


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for entire test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def vulnerable_client():
    """Sync test client for the vulnerable demo app."""
    return TestClient(vulnerable_app)


@pytest.fixture
def hardened_client():
    """Sync test client for the hardened demo app."""
    return TestClient(hardened_app)


@pytest.fixture
def vulnerable_base_url():
    return "http://testserver"


@pytest.fixture
def hardened_base_url():
    return "http://testserver-hardened"
