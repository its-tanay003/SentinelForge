"""Security headers scanner."""
from dataclasses import dataclass, field
from typing import Optional
import httpx
from app.config import settings


SEVERITY_WEIGHTS = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}

REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "id": "HDR-001",
        "title": "Missing Content-Security-Policy Header",
        "severity": "High",
        "remediation": (
            "Add a Content-Security-Policy header to restrict resource loading. "
            "Start with: Content-Security-Policy: default-src 'self'; script-src 'self'"
        ),
    },
    "Strict-Transport-Security": {
        "id": "HDR-002",
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "severity": "High",
        "remediation": (
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ),
    },
    "X-Frame-Options": {
        "id": "HDR-003",
        "title": "Missing X-Frame-Options Header",
        "severity": "Medium",
        "remediation": (
            "Add: X-Frame-Options: DENY  (or SAMEORIGIN if framing within same origin is needed)"
        ),
    },
    "X-Content-Type-Options": {
        "id": "HDR-004",
        "title": "Missing X-Content-Type-Options Header",
        "severity": "Low",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "id": "HDR-005",
        "title": "Missing Referrer-Policy Header",
        "severity": "Low",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "id": "HDR-006",
        "title": "Missing Permissions-Policy Header",
        "severity": "Low",
        "remediation": (
            "Add: Permissions-Policy: geolocation=(), microphone=(), camera=() "
            "to restrict browser feature access."
        ),
    },
}

WEAK_CSP_PATTERNS = ["'unsafe-inline'", "'unsafe-eval'", "*", "data:"]


@dataclass
class ScanFinding:
    finding_id: str
    title: str
    category: str
    severity: str
    evidence: str
    remediation: str


async def scan_headers(url: str) -> list[ScanFinding]:
    """Scan a URL for missing or weak security headers."""
    findings: list[ScanFinding] = []

    try:
        async with httpx.AsyncClient(
            verify=False, timeout=settings.HTTP_TIMEOUT, follow_redirects=True
        ) as client:
            resp = await client.get(url)
            headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception as e:
        findings.append(
            ScanFinding(
                finding_id="HDR-000",
                title="Failed to Connect to Target",
                category="headers",
                severity="Critical",
                evidence=f"Connection error: {e}",
                remediation="Ensure the target URL is reachable and correct.",
            )
        )
        return findings

    # Check required headers
    for header_name, meta in REQUIRED_HEADERS.items():
        if header_name.lower() not in headers:
            findings.append(
                ScanFinding(
                    finding_id=meta["id"],
                    title=meta["title"],
                    category="headers",
                    severity=meta["severity"],
                    evidence=f"Header '{header_name}' not present in HTTP response.",
                    remediation=meta["remediation"],
                )
            )

    # Check CSP quality if present
    csp = headers.get("content-security-policy", "")
    if csp:
        for pattern in WEAK_CSP_PATTERNS:
            if pattern in csp:
                findings.append(
                    ScanFinding(
                        finding_id="HDR-007",
                        title=f"Weak Content-Security-Policy: Contains '{pattern}'",
                        category="headers",
                        severity="Medium",
                        evidence=f"CSP value: {csp[:200]}",
                        remediation=(
                            f"Remove '{pattern}' from CSP. Use nonces or hashes for inline scripts. "
                            "Avoid wildcard sources."
                        ),
                    )
                )
                break  # one finding per URL for weak CSP

    # Check HSTS quality if present
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        if "includesubdomains" not in hsts.lower():
            findings.append(
                ScanFinding(
                    finding_id="HDR-008",
                    title="HSTS Missing includeSubDomains Directive",
                    category="headers",
                    severity="Info",
                    evidence=f"HSTS value: {hsts}",
                    remediation="Add 'includeSubDomains' to HSTS header.",
                )
            )
        # Check max-age
        try:
            max_age_part = [p for p in hsts.split(";") if "max-age" in p.lower()]
            if max_age_part:
                max_age = int(max_age_part[0].split("=")[1].strip())
                if max_age < 15768000:  # < 6 months
                    findings.append(
                        ScanFinding(
                            finding_id="HDR-009",
                            title="HSTS max-age Too Short",
                            category="headers",
                            severity="Low",
                            evidence=f"max-age={max_age} (minimum recommended: 15768000)",
                            remediation="Set HSTS max-age to at least 31536000 (1 year).",
                        )
                    )
        except (ValueError, IndexError):
            pass

    # Check Server header disclosure
    server = headers.get("server", "")
    if server and any(v in server.lower() for v in ["apache", "nginx", "iis", "python", "uvicorn"]):
        findings.append(
            ScanFinding(
                finding_id="HDR-010",
                title="Server Version Disclosure",
                category="headers",
                severity="Info",
                evidence=f"Server: {server}",
                remediation="Remove or obfuscate the Server header to prevent version fingerprinting.",
            )
        )

    # Check X-Powered-By
    xpb = headers.get("x-powered-by", "")
    if xpb:
        findings.append(
            ScanFinding(
                finding_id="HDR-011",
                title="X-Powered-By Header Exposes Technology",
                category="headers",
                severity="Info",
                evidence=f"X-Powered-By: {xpb}",
                remediation="Remove the X-Powered-By header from server configuration.",
            )
        )

    return findings
