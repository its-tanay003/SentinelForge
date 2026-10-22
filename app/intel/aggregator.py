"""Threat intelligence aggregator - combines VirusTotal + OTX results."""
import json
import hashlib
from datetime import datetime, timedelta
from urllib.parse import urlparse
from sqlalchemy.orm import Session
from app.config import settings
from app.intel.virustotal import get_virustotal_intel
from app.intel.otx import get_otx_intel
from app.models import IntelCache


def _extract_domain(url: str) -> str:
    """Extract domain/hostname from URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname or url
    # Remove port if present
    if ":" in hostname:
        hostname = hostname.split(":")[0]
    return hostname


def _cache_key(domain: str) -> str:
    return f"intel:{hashlib.md5(domain.encode()).hexdigest()}"


def _is_cache_valid(cached: IntelCache) -> bool:
    ttl = timedelta(seconds=settings.INTEL_CACHE_TTL)
    return datetime.utcnow() - cached.created_at < ttl


async def aggregate_intel(url: str, db: Session) -> dict:
    """
    Fetch and aggregate threat intelligence from all sources.
    Uses caching to avoid redundant API calls.
    """
    domain = _extract_domain(url)
    cache_key = _cache_key(domain)

    # Check cache
    cached = db.query(IntelCache).filter(IntelCache.cache_key == cache_key).first()
    if cached and _is_cache_valid(cached):
        data = json.loads(cached.data)
        data["from_cache"] = True
        return data

    # Fetch from sources
    vt_data = await get_virustotal_intel(domain)
    otx_data = await get_otx_intel(domain)

    # Compute aggregate reputation score (0-100, higher = riskier)
    risk_score = _compute_intel_risk_score(vt_data, otx_data)

    result = {
        "domain": domain,
        "url": url,
        "virustotal": vt_data,
        "otx": otx_data,
        "aggregate": {
            "risk_score": risk_score,
            "malicious_count": vt_data.get("last_analysis_stats", {}).get("malicious", 0),
            "suspicious_count": vt_data.get("last_analysis_stats", {}).get("suspicious", 0),
            "pulse_count": otx_data.get("pulse_count", 0),
            "tags": list(set(vt_data.get("tags", []) + otx_data.get("tags", []))),
            "is_mock": vt_data.get("is_mock", False) or otx_data.get("is_mock", False),
        },
        "retrieved_at": datetime.utcnow().isoformat(),
        "from_cache": False,
    }

    # Save to cache
    if cached:
        cached.data = json.dumps(result)
        cached.created_at = datetime.utcnow()
    else:
        db.add(IntelCache(cache_key=cache_key, data=json.dumps(result)))
    db.commit()

    return result


def _compute_intel_risk_score(vt_data: dict, otx_data: dict) -> float:
    """
    Compute a 0-100 intel risk score based on threat intelligence.
    Higher score = higher risk.
    """
    score = 0.0

    # VirusTotal signals
    stats = vt_data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1

    # Malicious detections: up to 50 points
    score += min(50.0, (malicious / total) * 100 * 0.5)
    # Suspicious: up to 15 points
    score += min(15.0, (suspicious / total) * 100 * 0.15)

    # OTX pulses: each pulse adds risk
    pulse_count = otx_data.get("pulse_count", 0)
    score += min(25.0, pulse_count * 5.0)

    # Negative VT reputation
    vt_rep = vt_data.get("reputation", 0)
    if vt_rep < 0:
        score += min(10.0, abs(vt_rep) * 0.5)

    return round(min(100.0, score), 2)
