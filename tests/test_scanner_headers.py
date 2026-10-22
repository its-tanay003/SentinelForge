"""Tests for the security headers scanner."""
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch, MagicMock
import httpx
from app.scanner.headers import scan_headers, ScanFinding


def make_mock_response(headers: dict, status_code: int = 200, url: str = "http://test.example.com"):
    """Create a mock httpx response with the given headers."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = httpx.Headers(headers)
    mock_resp.url = httpx.URL(url)
    return mock_resp


class TestHeadersScanner:

    @pytest.mark.asyncio
    async def test_missing_all_security_headers(self):
        """All security headers absent should produce findings."""
        mock_resp = make_mock_response({
            "content-type": "text/html",
            "server": "Apache/2.4.41",
        })

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp

            findings = await scan_headers("http://test.example.com")

        finding_ids = [f.finding_id for f in findings]
        assert "HDR-001" in finding_ids, "Missing CSP should be flagged"
        assert "HDR-002" in finding_ids, "Missing HSTS should be flagged"
        assert "HDR-003" in finding_ids, "Missing X-Frame-Options should be flagged"
        assert "HDR-004" in finding_ids, "Missing X-Content-Type-Options should be flagged"
        assert "HDR-010" in finding_ids, "Server version disclosure should be flagged"

    @pytest.mark.asyncio
    async def test_all_security_headers_present(self):
        """No findings for well-configured headers."""
        mock_resp = make_mock_response({
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()",
        })

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp

            findings = await scan_headers("http://test.example.com")

        finding_ids = [f.finding_id for f in findings]
        # None of the required header findings should be present
        assert "HDR-001" not in finding_ids
        assert "HDR-002" not in finding_ids
        assert "HDR-003" not in finding_ids
        assert "HDR-004" not in finding_ids

    @pytest.mark.asyncio
    async def test_weak_csp_detected(self):
        """Weak CSP patterns should be flagged."""
        mock_resp = make_mock_response({
            "content-security-policy": "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()",
        })

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp

            findings = await scan_headers("http://test.example.com")

        finding_ids = [f.finding_id for f in findings]
        assert "HDR-007" in finding_ids, "Weak CSP ('unsafe-inline') should be flagged"

    @pytest.mark.asyncio
    async def test_connection_error_produces_critical_finding(self):
        """Network connection errors should produce a critical finding."""
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.side_effect = httpx.ConnectError("Connection refused")

            findings = await scan_headers("http://unreachable.invalid")

        assert len(findings) == 1
        assert findings[0].finding_id == "HDR-000"
        assert findings[0].severity == "Critical"

    @pytest.mark.asyncio
    async def test_hsts_missing_include_subdomains(self):
        """HSTS without includeSubDomains should produce an info finding."""
        mock_resp = make_mock_response({
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        })

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp

            findings = await scan_headers("https://test.example.com")

        finding_ids = [f.finding_id for f in findings]
        assert "HDR-008" in finding_ids, "HSTS without includeSubDomains should be flagged"

    def test_scan_finding_dataclass(self):
        """ScanFinding dataclass should store all fields correctly."""
        f = ScanFinding(
            finding_id="HDR-001",
            title="Test Finding",
            category="headers",
            severity="High",
            evidence="Header X not present",
            remediation="Add header X",
        )
        assert f.finding_id == "HDR-001"
        assert f.severity == "High"
        assert f.category == "headers"
