"""AlienVault OTX threat intelligence integration."""
import httpx
from app.config import settings
from app.intel.mock_intel import generate_mock_otx


OTX_BASE_URL = "https://otx.alienvault.com/api/v1"


async def get_otx_intel(domain: str) -> dict:
    """
    Fetch threat intel from AlienVault OTX API.
    Falls back to mock data if API key is missing or request fails.
    """
    if not settings.OTX_API_KEY:
        return generate_mock_otx(domain)

    try:
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as client:
            # Get general indicator info
            resp = await client.get(
                f"{OTX_BASE_URL}/indicators/domain/{domain}/general",
                headers={"X-OTX-API-KEY": settings.OTX_API_KEY},
            )

            if resp.status_code == 200:
                general = resp.json()

                # Try to get URL list
                pulses = general.get("pulse_info", {}).get("pulses", [])
                pulse_summary = [
                    {
                        "id": p.get("id"),
                        "name": p.get("name"),
                        "created": p.get("created"),
                        "author_name": p.get("author_name"),
                        "tags": p.get("tags", []),
                    }
                    for p in pulses[:10]  # Limit to 10 pulses
                ]

                return {
                    "source": "otx",
                    "is_mock": False,
                    "domain": domain,
                    "pulse_count": general.get("pulse_info", {}).get("count", 0),
                    "pulses": pulse_summary,
                    "malicious_urls": 0,  # Would need separate endpoint
                    "passive_dns": [],
                    "tags": list({tag for p in pulse_summary for tag in p.get("tags", [])}),
                    "reputation": general.get("reputation", 0),
                    "retrieved_at": general.get("last_fetched", ""),
                }
            elif resp.status_code == 401:
                result = generate_mock_otx(domain)
                result["mock_notice"] = "⚠️ MOCK DATA - Invalid OTX API key"
                return result
            else:
                result = generate_mock_otx(domain)
                result["mock_notice"] = f"⚠️ MOCK DATA - OTX API returned HTTP {resp.status_code}"
                return result

    except httpx.RequestError as e:
        result = generate_mock_otx(domain)
        result["mock_notice"] = f"⚠️ MOCK DATA - Network error: {e}"
        return result
    except Exception as e:
        result = generate_mock_otx(domain)
        result["mock_notice"] = f"⚠️ MOCK DATA - Unexpected error: {e}"
        return result
