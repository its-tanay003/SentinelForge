"""Tests for CORS scanner."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx
from app.scanner.cors import scan_cors


def make_cors_response(acao="", acac="", status=200):
    mock_resp = MagicMock()
    mock_resp.status_code = status
    headers = {}
    if acao:
        headers["access-control-allow-origin"] = acao
    if acac:
        headers["access-control-allow-credentials"] = acac
    mock_resp.headers = httpx.Headers(headers)
    return mock_resp


class TestCORSScanner:

    @pytest.mark.asyncio
    async def test_wildcard_cors_detected(self):
        """Wildcard CORS should be flagged as High."""
        # Two requests: one with evil origin, one with null
        responses = [
            make_cors_response(acao="*"),  # evil origin response
            make_cors_response(acao="*"),  # null origin response
            make_cors_response(),          # OPTIONS preflight
        ]
        call_count = 0

        async def mock_get(*args, **kwargs):
            nonlocal call_count
            r = responses[min(call_count, len(responses)-1)]
            call_count += 1
            return r

        async def mock_options(*args, **kwargs):
            return make_cors_response()

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.side_effect = mock_get
            mock_client.options.side_effect = mock_options

            findings = await scan_cors("http://test.example.com")

        finding_ids = [f.finding_id for f in findings]
        assert "CRS-002" in finding_ids, "Wildcard CORS should produce CRS-002"

    @pytest.mark.asyncio
    async def test_wildcard_with_credentials_critical(self):
        """Wildcard CORS + credentials should be Critical."""
        responses = [
            make_cors_response(acao="*", acac="true"),
            make_cors_response(acao="*", acac="true"),
        ]
        call_count = 0

        async def mock_get(*args, **kwargs):
            nonlocal call_count
            r = responses[min(call_count, len(responses)-1)]
            call_count += 1
            return r

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.side_effect = mock_get
            mock_client.options.return_value = make_cors_response()

            findings = await scan_cors("http://test.example.com")

        critical_findings = [f for f in findings if f.severity == "Critical"]
        assert len(critical_findings) >= 1, "Wildcard + credentials should produce Critical finding"
        assert any(f.finding_id == "CRS-001" for f in critical_findings)

    @pytest.mark.asyncio
    async def test_reflected_origin_detected(self):
        """Reflected arbitrary origin should be flagged."""
        evil_origin = "https://evil.attacker.com"

        async def mock_get(url, headers=None, **kwargs):
            origin = (headers or {}).get("Origin", "")
            if origin == evil_origin:
                return make_cors_response(acao=evil_origin)
            return make_cors_response()

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.side_effect = mock_get
            mock_client.options.return_value = make_cors_response()

            findings = await scan_cors("http://test.example.com")

        finding_ids = [f.finding_id for f in findings]
        assert "CRS-003" in finding_ids, "Reflected origin should produce CRS-003"

    @pytest.mark.asyncio
    async def test_no_cors_headers_no_findings(self):
        """No CORS headers = no CORS findings."""
        async def mock_get(*args, **kwargs):
            return make_cors_response()  # No ACAO header

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.side_effect = mock_get
            mock_client.options.return_value = make_cors_response()

            findings = await scan_cors("http://test.example.com")

        cors_findings = [f for f in findings if f.finding_id.startswith("CRS-")]
        assert len(cors_findings) == 0, "No CORS headers should produce no CORS findings"
