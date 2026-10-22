"""Mock threat intelligence data for when API keys are unavailable."""
import random
from datetime import datetime


def generate_mock_virustotal(domain: str) -> dict:
    """Generate realistic mock VirusTotal data."""
    seed = sum(ord(c) for c in domain)
    random.seed(seed)

    malicious = random.randint(0, 8)
    suspicious = random.randint(0, 5)
    harmless = random.randint(50, 80)
    undetected = random.randint(5, 20)

    return {
        "source": "virustotal",
        "is_mock": True,
        "domain": domain,
        "last_analysis_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": 0,
        },
        "reputation": random.randint(-10, 10),
        "total_votes": {
            "harmless": random.randint(0, 20),
            "malicious": random.randint(0, 5),
        },
        "categories": random.choice([
            {"Forcepoint ThreatSeeker": "information technology", "Sophos": "information technology"},
            {"Forcepoint ThreatSeeker": "web-based email"},
            {"Webroot": "phishing", "Sophos": "malware"},
        ]),
        "tags": random.sample(
            ["dynamic-dns", "self-signed-cert", "parked", "suspicious", "cdn", "shopping"],
            k=random.randint(0, 3)
        ),
        "mock_notice": "⚠️ MOCK DATA - No VirusTotal API key configured",
        "retrieved_at": datetime.utcnow().isoformat(),
    }


def generate_mock_otx(domain: str) -> dict:
    """Generate realistic mock AlienVault OTX data."""
    seed = sum(ord(c) for c in domain) + 42
    random.seed(seed)

    pulse_count = random.randint(0, 5)
    pulses = []
    for i in range(pulse_count):
        pulses.append({
            "id": f"mock-pulse-{i+1:04d}",
            "name": random.choice([
                "Suspicious Infrastructure",
                "Phishing Campaign Q4",
                "Known Malware C2",
                "Dark Web Indicator",
                "Botnet Activity",
            ]),
            "created": f"2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}T00:00:00",
            "author_name": "AlienVault_Mock",
            "tags": random.sample(["phishing", "malware", "c2", "ransomware", "apt"], k=random.randint(1, 3)),
        })

    malicious_urls = random.randint(0, 3)
    passive_dns = [
        {"hostname": domain, "address": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"}
        for _ in range(random.randint(1, 3))
    ]

    return {
        "source": "otx",
        "is_mock": True,
        "domain": domain,
        "pulse_count": pulse_count,
        "pulses": pulses,
        "malicious_urls": malicious_urls,
        "passive_dns": passive_dns,
        "tags": list({tag for p in pulses for tag in p.get("tags", [])}),
        "reputation": -pulse_count * 10,
        "mock_notice": "⚠️ MOCK DATA - No OTX API key configured",
        "retrieved_at": datetime.utcnow().isoformat(),
    }
