"""Tests for cookie scanner."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx
from app.scanner.cookies import scan_cookies


def make_cookie_response(set_cookie_values: list[str]):
    """Create a mock response with the given Set-Cookie headers."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    
    # Build raw headers with multiple Set-Cookie
    raw = []
    for v in set_cookie_values:
        raw.append((b"set-cookie", v.encode()))
    raw.append((b"content-type", b"text/html"))
    
    mock_resp.headers = httpx.Headers(raw_items=raw)
    return mock_resp


class TestCookieScanner:

    @pytest.mark.asyncio
    async def test_insecure_cookie_all_flags_missing(self):
        """Cookie with no flags should produce 3 findings."""
        mock_resp = make_cookie_response(["session=abc123"])

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp

            findings = await scan_cookies("http://test.example.com")

        assert len(findings) >= 2, "Should find at least HttpOnly and SameSite missing"
        finding_ids = [f.finding_id for f in findings]
        # Check for HttpOnly and SameSite findings  
        has_httponly = any("Missing HttpOnly" in f.title for f in findings)
        has_samesite = any("Missing SameSite" in f.title for f in findings)
        assert has_httponly, "Missing HttpOnly should be flagged"
        assert has_samesite, "Missing SameSite should be flagged"

    @pytest.mark.asyncio
    async def test_secure_cookie_no_findings(self):
        """Well-configured cookie should produce no findings."""
        mock_resp = make_cookie_response([
            "session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600"
        ])

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp

            findings = await scan_cookies("https://test.example.com")

        assert len(findings) == 0, "Secure cookie with all flags should have no findings"

    @pytest.mark.asyncio
    async def test_samesite_none_without_secure(self):
        """SameSite=None without Secure flag should be flagged High."""
        mock_resp = make_cookie_response([
            "session=abc123; HttpOnly; SameSite=None"
        ])

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp

            findings = await scan_cookies("http://test.example.com")

        high_findings = [f for f in findings if f.severity == "High"]
        samesite_none_finding = [f for f in findings if "SameSite=None" in f.title]
        assert len(samesite_none_finding) >= 1, "SameSite=None without Secure should be High"

    @pytest.mark.asyncio
    async def test_no_cookies_no_findings(self):
        """Response without cookies should produce no findings."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = httpx.Headers({"content-type": "text/html"})

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp

            findings = await scan_cookies("http://test.example.com")

        assert len(findings) == 0, "No cookies should produce no cookie findings"
