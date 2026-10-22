"""VirusTotal threat intelligence integration."""
import httpx
from app.config import settings
from app.intel.mock_intel import generate_mock_virustotal


VT_BASE_URL = "https://www.virustotal.com/api/v3"


async def get_virustotal_intel(domain: str) -> dict:
    """
    Fetch threat intel from VirusTotal API.
    Falls back to mock data if API key is missing or request fails.
    """
    if not settings.VIRUSTOTAL_API_KEY:
        return generate_mock_virustotal(domain)

    try:
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as client:
            resp = await client.get(
                f"{VT_BASE_URL}/domains/{domain}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )

            if resp.status_code == 200:
                data = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                return {
                    "source": "virustotal",
                    "is_mock": False,
                    "domain": domain,
                    "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                    "reputation": attrs.get("reputation", 0),
                    "total_votes": attrs.get("total_votes", {}),
                    "categories": attrs.get("categories", {}),
                    "tags": attrs.get("tags", []),
                    "retrieved_at": attrs.get("last_analysis_date", ""),
                }
            elif resp.status_code == 401:
                # Invalid key - fall back to mock
                result = generate_mock_virustotal(domain)
                result["mock_notice"] = "⚠️ MOCK DATA - Invalid VirusTotal API key"
                return result
            elif resp.status_code == 404:
                return {
                    "source": "virustotal",
                    "is_mock": False,
                    "domain": domain,
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                    "reputation": 0,
                    "total_votes": {},
                    "categories": {},
                    "tags": [],
                    "note": "Domain not found in VirusTotal database",
                    "retrieved_at": "",
                }
            else:
                result = generate_mock_virustotal(domain)
                result["mock_notice"] = f"⚠️ MOCK DATA - VirusTotal API returned HTTP {resp.status_code}"
                return result

    except httpx.RequestError as e:
        result = generate_mock_virustotal(domain)
        result["mock_notice"] = f"⚠️ MOCK DATA - Network error: {e}"
        return result
    except Exception as e:
        result = generate_mock_virustotal(domain)
        result["mock_notice"] = f"⚠️ MOCK DATA - Unexpected error: {e}"
        return result
