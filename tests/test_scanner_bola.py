"""Tests for BOLA/IDOR scanner."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx
from app.scanner.bola import scan_bola


def make_bola_response(status: int, body: dict):
    mock_resp = MagicMock()
    mock_resp.status_code = status
    mock_resp.text = str(body)
    mock_resp.content = str(body).encode()
    return mock_resp


class TestBOLAScanner:

    @pytest.mark.asyncio
    async def test_idor_all_accessible(self):
        """All object IDs accessible = BOLA detected."""
        responses = {
            "1": make_bola_response(200, {"id": 1, "name": "Alice"}),
            "2": make_bola_response(200, {"id": 2, "name": "Bob"}),
            "3": make_bola_response(200, {"id": 3, "name": "Carol"}),
        }

        call_count = [0]

        async def mock_get(url, **kwargs):
            # Extract ID from URL
            for obj_id, resp in responses.items():
                if url.endswith(f"/{obj_id}"):
                    return resp
            return make_bola_response(404, {"error": "not found"})

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.side_effect = mock_get

            findings = await scan_bola("http://test.example.com", "/api/users/{id}", ["1", "2", "3"])

        finding_ids = [f.finding_id for f in findings]
        assert "BOL-001" in finding_ids, "Accessible without auth should produce BOL-001"
        assert "BOL-002" in finding_ids, "Different IDs returning different data should produce BOL-002"

    @pytest.mark.asyncio
    async def test_all_endpoints_return_401(self):
        """All 401 responses = good, info finding."""
        async def mock_get(url, **kwargs):
            return make_bola_response(401, {"error": "unauthorized"})

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.side_effect = mock_get

            findings = await scan_bola("http://test.example.com", "/api/users/{id}", ["1", "2", "3"])

        finding_ids = [f.finding_id for f in findings]
        # No HIGH findings, only info
        high_critical = [f for f in findings if f.severity in ("High", "Critical")]
        assert len(high_critical) == 0, "401 responses should not produce High/Critical findings"
        assert "BOL-INFO-001" in finding_ids, "401 responses should produce info finding"

    @pytest.mark.asyncio
    async def test_single_id_accessible(self):
        """Single accessible ID should produce BOL-001 but not BOL-002."""
        async def mock_get(url, **kwargs):
            if url.endswith("/1"):
                return make_bola_response(200, {"id": 1, "data": "secret"})
            return make_bola_response(404, {"error": "not found"})

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.side_effect = mock_get

            findings = await scan_bola("http://test.example.com", "/api/users/{id}", ["1", "2"])

        finding_ids = [f.finding_id for f in findings]
        assert "BOL-001" in finding_ids
        # BOL-002 requires 2+ accessible IDs with different content
        assert "BOL-002" not in finding_ids

    @pytest.mark.asyncio
    async def test_demo_target_has_idor(self, vulnerable_client):
        """The vulnerable demo target should have IDOR vulnerabilities."""
        # Test that the vulnerable app returns user data without auth
        resp = vulnerable_client.get("/api/users/1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == 1
        assert "name" in data

        # Test that different IDs return different users
        resp2 = vulnerable_client.get("/api/users/2")
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["id"] == 2
        assert data["name"] != data2["name"]

    def test_hardened_target_requires_auth(self, hardened_client):
        """The hardened demo target should require authentication."""
        resp = hardened_client.get("/api/users/1")
        assert resp.status_code == 401

    def test_hardened_target_rejects_invalid_token(self, hardened_client):
        """Invalid token should return 401."""
        resp = hardened_client.get(
            "/api/users/1",
            headers={"Authorization": "Bearer invalid-token"}
        )
        assert resp.status_code == 401
